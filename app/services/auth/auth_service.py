# app/services/auth/auth_service.py
import logging
from datetime import datetime, timezone

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
import json

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
            active_sessions = [
                {
                    "device": session.get("device"),
                    "browser": session.get("browser"),
                    "os": session.get("os"),
                    "ip": session.get("ip"),
                    "created_at": session.get("created_at"),
                    "role": session.get("role")  # اضافه کردن نقش به خروجی
                }
                for session in sessions.values()
            ]
            logger.info(f"Retrieved {len(active_sessions)} active sessions for user: {user_id}")
            return {"active_sessions": active_sessions}
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

    async def login(self, request: LoginRequest, device_info: dict = None) -> dict:
        phone_number = self._normalize_phone(request.phone_number)
        role = request.role
        if not phone_number or not role:
            raise HTTPException(status_code=400, detail="Phone number and role cannot be empty.")

        user = await self.auth_repository.get_user_by_phone(phone_number)
        otp_type = "login" if user else "register"
        otp_code, otp_id = self.otp_manager.generate_otp(phone_number, otp_type, device_info)

        if user:
            user_id = str(user["_id"])
            roles = user.get("roles", [])
            if role not in roles:
                roles.append(role)
                await self.auth_repository.users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"roles": roles, "updated_at": datetime.now(timezone.utc)}}
                )
        else:
            user_id = f"temp-{phone_number}"
            roles = [role]

        temp_access_token = self.jwt_manager.create_access_token(user_id, roles, phone_number, temp=True)
        redis_key = f"login:{phone_number}:{otp_id}"
        redis_data = {"otp_id": otp_id, "access_token": temp_access_token, "role": role}
        self.redis_service.set_with_expiry(redis_key, json.dumps(redis_data), 600)

        await self.sms_service.send_sms(phone_number, f"Your {otp_type} OTP code: {otp_code}")
        logger.info(f"{otp_type.capitalize()} OTP sent to: {phone_number}")
        return {"message": f"OTP sent for {otp_type}.", "action": otp_type}

    async def verify_otp(self, request: OTPVerificationRequest, http_request: Request = None):
        try:
            phone_number = self._normalize_phone(request.phone_number)
            otp_code = request.otp_code
            role = request.role  # نقش درخواست‌شده
            if not phone_number or not otp_code or not role:
                raise HTTPException(status_code=400, detail="Phone number, OTP code, and role are required.")

            redis_keys = self.redis_service.client.keys(f"login:{phone_number}:*")
            if not redis_keys:
                raise HTTPException(status_code=400, detail="No valid OTP request found or expired.")

            latest_key = redis_keys[-1]
            stored_data = self.redis_service.get(latest_key)
            if not stored_data:
                raise HTTPException(status_code=400, detail="OTP data expired or not found.")

            redis_data = json.loads(stored_data)
            otp_id = redis_data["otp_id"]

            success, otp_type = self.otp_manager.verify_otp(phone_number, otp_code, otp_id)
            if not success:
                raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

            user = await self.auth_repository.get_user_by_phone(phone_number)
            action = otp_type

            if otp_type == "register" or (user and role not in user.get("roles", [])):
                if not user:
                    user_id = await self.auth_repository.create_user(phone_number, role)
                    roles = [role]
                    message = "Registration completed successfully."
                else:
                    user_id = str(user["_id"])
                    roles = user.get("roles", [])
                    if role not in roles:
                        roles.append(role)
                        await self.auth_repository.users.update_one(
                            {"_id": user["_id"]},
                            {"$set": {"roles": roles, "updated_at": datetime.now(timezone.utc)}}
                        )
                    message = "Role added and login successful."
            else:
                user_id = str(user["_id"])
                roles = user.get("roles", [])
                message = "Login successful."
                action = "login"

            access_token = self.jwt_manager.create_access_token(user_id, roles, phone_number)
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
            # پاس دادن نقش به store_session
            await self.redis_service.store_session(user_id, session_id, device_info, role)
            self.redis_service.delete(latest_key)

            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                message=message,
                action=action
            )
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_otp for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying OTP.")