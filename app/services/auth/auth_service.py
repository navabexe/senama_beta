import logging
from fastapi import HTTPException, Request
from user_agents import parse
from app.security.otp import OTPManager
from app.security.jwt import JWTManager
from app.domain.schemas.auth_schema import LoginRequest, OTPVerificationRequest, TokenResponse
from infrastructure.database.repository.auth_repository import AuthRepository
from infrastructure.caching.redis_service import RedisService
from infrastructure.caching.blacklist import BlacklistService
from infrastructure.external.sms_service import SMSService
from infrastructure.external.notification_service import NotificationService
from pymongo.errors import DuplicateKeyError

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self):
        try:
            self.auth_repository = AuthRepository()
            self.notification_service = NotificationService(mock_mode=True)
            self.redis_service = RedisService(notification_service=self.notification_service)
            self.blacklist_service = BlacklistService()
            self.sms_service = SMSService(mock_mode=True)
            self.otp_manager = OTPManager()
            self.jwt_manager = JWTManager()
            logger.info("AuthService initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize AuthService: {str(e)}", exc_info=True)
            raise Exception("AuthService initialization failed.")

    def _normalize_phone(self, phone_number: str) -> str:
        """Normalize phone number by removing spaces and dashes."""
        return phone_number.replace(" ", "").replace("-", "")

    async def logout(self, user_id: str, session_id: str = None) -> dict:
        try:
            if not user_id:
                logger.error("User ID is empty in logout.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            if session_id:
                self.redis_service.delete_session(user_id, session_id)
                logger.info(f"Session {session_id} logged out for user: {user_id}")
            else:
                self.redis_service.delete_all_sessions(user_id)
                logger.info(f"All sessions logged out for user: {user_id}")

            self.blacklist_service.add_to_blacklist(user_id)
            return {"message": "Successfully logged out."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in logout for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during logout.")

    async def get_active_sessions(self, user_id: str) -> dict:
        try:
            if not user_id:
                logger.error("User ID is empty in get_active_sessions.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            sessions = self.redis_service.get_user_sessions(user_id)
            logger.info(f"Retrieved {len(sessions)} active sessions for user: {user_id}")
            return {"active_sessions": list(sessions.values())}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_active_sessions for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving sessions.")

    async def request_account_deletion(self, phone_number: str, otp_code: str, otp_id: str) -> dict:
        try:
            phone_number = self._normalize_phone(phone_number)
            if not phone_number or not otp_code or not otp_id:
                logger.error("Phone number, OTP code, or OTP ID is empty in request_account_deletion.")
                raise HTTPException(status_code=400, detail="Phone number, OTP code, and OTP ID are required.")

            success, otp_type = self.otp_manager.verify_otp(phone_number, otp_code, otp_id)
            if not success:
                logger.warning(f"OTP verification failed for account deletion: {phone_number}")
                raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
            if otp_type != "login":
                logger.warning(f"Invalid OTP type for deletion request: {otp_type}")
                raise HTTPException(status_code=400, detail="OTP must be a login OTP for account deletion.")

            user = await self.auth_repository.get_user_by_phone(phone_number)
            if not user:
                logger.warning(f"User not found for deletion request: {phone_number}")
                raise HTTPException(status_code=404, detail="User not found.")

            await self.auth_repository.update_user_status(user["_id"], "pending_deletion")
            self.redis_service.set_with_expiry(f"deletion:{phone_number}", "pending", 30 * 24 * 3600)  # 30 days
            await self.notification_service.send_notification(
                phone_number, "Account Deletion Requested", "Your account will be deleted in 30 days."
            )
            logger.info(f"Account deletion requested for phone: {phone_number}")
            return {"message": "Account deletion request registered."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in request_account_deletion for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error requesting account deletion.")

    async def force_logout(self, user_id: str) -> dict:
        try:
            if not user_id:
                logger.error("User ID is empty in force_logout.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            logger.info(f"Attempting to force logout for user_id: {user_id}")

            user = await self.auth_repository.get_user_by_id(user_id)
            if not user:
                logger.warning(f"No user found with ID: {user_id}")
                raise HTTPException(status_code=404, detail="User not found.")

            sessions_before = self.redis_service.get_user_sessions(user_id)
            refresh_tokens = self.redis_service.get_all_refresh_tokens(user_id)
            if not sessions_before and not refresh_tokens:
                logger.warning(f"No active sessions or tokens found for user: {user_id}")
                raise HTTPException(status_code=404, detail="No active sessions or tokens found for this user.")

            logger.debug(f"Sessions before force logout for {user_id}: {len(sessions_before)}")
            logger.debug(f"Refresh tokens before force logout for {user_id}: {len(refresh_tokens)}")

            self.redis_service.delete_all_sessions(user_id)
            if refresh_tokens:
                for token in refresh_tokens:
                    self.blacklist_service.add_to_blacklist(token)
                self.redis_service.delete_all_refresh_tokens(user_id)

            sessions_after = self.redis_service.get_user_sessions(user_id)
            logger.debug(f"Sessions after force logout for {user_id}: {len(sessions_after)}")

            logger.info(f"Forced logout completed for user: {user_id}")
            return {"message": "All sessions and tokens terminated."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in force_logout for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during force logout.")

    async def verify_otp(self, request: OTPVerificationRequest, http_request: Request = None):
        try:
            phone_number = self._normalize_phone(request.phone_number)
            otp_code = request.otp_code
            otp_id = request.otp_id
            logger.info(f"Received verify_otp request: phone={phone_number}, otp_code={otp_code}, otp_id={otp_id}")
            if not phone_number or not otp_code or not otp_id:
                logger.error("Phone number, OTP code, or OTP ID is empty in verify_otp.")
                raise HTTPException(status_code=400, detail="Phone number, OTP code, and OTP ID are required.")

            success, otp_type = self.otp_manager.verify_otp(phone_number, otp_code, otp_id)
            if not success:
                logger.warning(f"OTP verification failed for phone: {phone_number}")
                raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

            user = await self.auth_repository.get_user_by_phone(phone_number)
            if otp_type == "register":
                if not user:
                    try:
                        user_id = await self.auth_repository.create_user(phone_number)
                        if not user_id:
                            logger.error(f"Failed to create user for phone: {phone_number}")
                            raise HTTPException(status_code=500, detail="Failed to create user account.")
                        roles = ["user"]
                        logger.info(f"New user created with ID: {user_id} for phone: {phone_number}")
                    except DuplicateKeyError:
                        logger.warning(f"Duplicate registration attempt for phone: {phone_number}")
                        raise HTTPException(status_code=400, detail="This phone number is already registered.")
                else:
                    logger.info(f"User already exists, treating register OTP as login for: {phone_number}")
                user_id = str(user["_id"]) if user else user_id
                roles = [user.get("role", "user")] if user else roles
            elif otp_type == "login":
                if not user:
                    logger.warning(f"User not found during login attempt: {phone_number}")
                    raise HTTPException(status_code=404, detail="This phone number is not registered.")
                user_id = str(user["_id"])
                roles = [user.get("role", "user")]
                logger.info(f"Existing user logged in with ID: {user_id} for phone: {phone_number}")
            else:
                logger.error(f"Invalid OTP type: {otp_type}")
                raise HTTPException(status_code=500, detail="Internal server error: Invalid OTP type.")

            access_token = self.jwt_manager.create_access_token(user_id, roles)
            refresh_token = self.jwt_manager.create_refresh_token(user_id)

            session_id = f"session-{otp_id}"
            user_agent_str = http_request.headers.get("User-Agent", "unknown") if http_request else "unknown"
            user_agent = parse(user_agent_str)
            device_info = {
                "device": user_agent.device.family,
                "browser": user_agent.browser.family,
                "os": user_agent.os.family,
                "ip": http_request.client.host if http_request else "127.0.0.1"
            }
            # اینجا await اضافه شده
            await self.redis_service.store_session(user_id, session_id, device_info)

            logger.info(f"Tokens issued for phone: {phone_number}, action: {otp_type}")
            return TokenResponse(access_token=access_token, refresh_token=refresh_token)
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_otp for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying OTP.")

    async def login(self, request: LoginRequest, device_info: dict = None) -> dict:
        try:
            phone_number = self._normalize_phone(request.phone_number)
            if not phone_number:
                logger.error("Phone number is empty in login.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            # دیباگ برای چک کردن دیتابیس
            user = await self.auth_repository.get_user_by_phone(phone_number)
            logger.debug(f"User lookup result for {phone_number}: {user}")

            if user:
                user_status = user.get("status")
                user_role = user.get("role", "user")
                if user_status == "blocked":
                    logger.warning(f"Blocked account attempted login: {phone_number}")
                    raise HTTPException(status_code=403, detail="Your account is blocked.")
                if user_role == "vendor" and user_status == "pending":
                    logger.warning(f"Pending vendor account attempted login: {phone_number}")
                    raise HTTPException(status_code=403, detail="Your account is pending admin approval.")

                otp_code, otp_id = self.otp_manager.generate_otp(phone_number, "login", device_info)
                await self.sms_service.send_sms(phone_number, f"Your login OTP code: {otp_code}")
                logger.info(f"Login OTP sent to existing user: {phone_number}")
                return {"message": "OTP sent for login.", "otp_id": otp_id, "action": "login"}
            else:
                otp_code, otp_id = self.otp_manager.generate_otp(phone_number, "register", device_info)
                await self.sms_service.send_sms(phone_number, f"Your registration OTP code: {otp_code}")
                logger.info(f"Registration OTP sent to new user: {phone_number}")
                return {"message": "OTP sent for registration.", "otp_id": otp_id, "action": "register"}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in login for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during login.")