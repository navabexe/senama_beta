# app/security/auth.py
import logging
from typing import Optional
from fastapi import HTTPException
from app.services.auth.auth_service import AuthService
from app.services.auth.token_service import TokenService
from app.services.auth.otp_service import OTPService
from app.domain.schemas.auth_schema import LoginRequest, OTPVerificationRequest, TokenResponse
from infrastructure.database.repository.auth_repository import AuthRepository
from infrastructure.caching.blacklist import BlacklistService
from infrastructure.caching.redis_service import RedisService
from infrastructure.external.sms_service import SMSService

logger = logging.getLogger(__name__)


class AuthManager:
    """
    High-level manager for authentication processes including registration, login, and logout.
    """

    def __init__(self):
        try:
            self.auth_service = AuthService()
            self.token_service = TokenService()
            self.otp_service = OTPService()
            self.auth_repository = AuthRepository()
            self.redis_service = RedisService()
            self.blacklist_service = BlacklistService()
            self.sms_service = SMSService()
            logger.info("AuthManager initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize AuthManager: {str(e)}", exc_info=True)
            raise Exception("AuthManager initialization failed.")

    async def register_user(self, request: LoginRequest) -> dict:
        """
        Registers a user by sending an OTP.
        """
        global phone_number
        try:
            phone_number = request.phone_number
            if not phone_number:
                logger.error("Phone number is empty in register_user.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            existing_user = await self.auth_repository.get_user_by_phone(phone_number)
            if existing_user:
                logger.warning(f"Phone number already registered: {phone_number}")
                raise HTTPException(status_code=400, detail="This phone number is already registered.")

            if not phone_number.startswith("+"):
                logger.error(f"Invalid phone number format: {phone_number}")
                raise HTTPException(status_code=400, detail="Phone number must be in international format (e.g., +98).")

            otp_code = self.otp_service.send_otp(phone_number)
            logger.info(f"Registration OTP sent to {phone_number}")
            return {"message": "OTP sent for registration."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in register_user for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during registration.")

    async def verify_otp(self, request: OTPVerificationRequest) -> TokenResponse:
        """
        Verifies OTP and completes registration or login.
        """
        global phone_number
        try:
            phone_number = request.phone_number
            otp_code = request.otp_code
            if not phone_number or not otp_code:
                logger.error("Phone number or OTP code is empty in verify_otp.")
                raise HTTPException(status_code=400, detail="Phone number and OTP code cannot be empty.")

            if not self.otp_service.verify_otp(phone_number, otp_code):
                logger.warning(f"OTP verification failed for {phone_number}")
                raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

            user = await self.auth_repository.get_user_by_phone(phone_number)
            if user:
                user_id = str(user["_id"])
            else:
                user_id = await self.auth_repository.create_user(phone_number)

            tokens = self.token_service.create_tokens(user_id)
            logger.info(f"OTP verified and tokens issued for {phone_number}")
            return TokenResponse(**tokens)
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_otp for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying OTP.")

    async def login(self, request: LoginRequest, device_info: Optional[dict] = None) -> dict:
        """
        Initiates login by sending an OTP.
        """
        global phone_number
        try:
            phone_number = request.phone_number
            if not phone_number:
                logger.error("Phone number is empty in login.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            user = await self.auth_repository.get_user_by_phone(phone_number)
            if not user:
                logger.warning(f"Phone number not registered: {phone_number}")
                raise HTTPException(status_code=404, detail="This phone number is not registered.")

            if user.get("status") == "blocked":
                logger.warning(f"Blocked account attempted login: {phone_number}")
                raise HTTPException(status_code=403, detail="Your account is blocked.")
            if user.get("role") == "vendor" and user.get("status") == "pending":
                logger.warning(f"Pending vendor account attempted login: {phone_number}")
                raise HTTPException(status_code=403, detail="Your account is pending admin approval.")

            otp_code = self.otp_service.send_otp(phone_number)
            logger.info(f"Login OTP sent to {phone_number}")
            return {"message": "OTP sent for login."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in login for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during login.")

    async def logout(self, user_id: str, session_id: Optional[str] = None) -> dict:
        """
        Logs out a user from a specific session or all sessions.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in logout.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            if session_id:
                self.redis_service.delete_session(user_id, session_id)
                logger.info(f"Logged out session {session_id} for user {user_id}")
            else:
                self.redis_service.delete_all_sessions(user_id)
                self.token_service.invalidate_user_tokens(user_id)
                logger.info(f"Logged out all sessions for user {user_id}")

            self.blacklist_service.add_to_blacklist(user_id)
            return {"message": "Successfully logged out."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in logout for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during logout.")

    async def force_logout(self, user_id: str) -> dict:
        """
        Forces logout of all sessions and tokens for a user by admin.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in force_logout.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            self.token_service.force_logout(user_id)
            logger.info(f"Forced logout completed for user {user_id}")
            return {"message": "All sessions and tokens terminated."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in force_logout for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during force logout.")