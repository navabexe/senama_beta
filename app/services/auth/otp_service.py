# app/services/auth/otp_service.py
import logging
from fastapi import HTTPException
from app.security.otp import OTPManager
from infrastructure.caching.redis_service import RedisService
from infrastructure.external.sms_service import SMSService
from app.core.config import settings

logger = logging.getLogger(__name__)


class OTPService:
    """
    Manages OTP sending and verification for authentication.
    """

    def __init__(self):
        try:
            self.redis_service = RedisService()
            self.sms_service = SMSService()
            self.otp_manager = OTPManager()
            self.OTP_EXPIRATION_MINUTES = settings.OTP_EXPIRE_MINUTES
            self.OTP_MAX_ATTEMPTS = 5
            self.OTP_COOLDOWN_SECONDS = 60
            logger.info("OTPService initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize OTPService: {str(e)}", exc_info=True)
            raise Exception("OTPService initialization failed.")

    async def send_otp(self, phone_number: str) -> dict:
        try:
            if not phone_number:
                logger.error("Phone number is empty in send_otp.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            # last_request = self.redis_service.get(f"otp_cooldown:{phone_number}")
            # if last_request:
            #     logger.warning(f"Cooldown active for phone: {phone_number}")
            #     raise HTTPException(
            #         status_code=429,
            #         detail=f"Please wait {self.OTP_COOLDOWN_SECONDS} seconds before requesting again."
            #     )

            otp_code = self.otp_manager.generate_otp(phone_number)
            logger.info(f"[MOCK] OTP for {phone_number}: {otp_code}")  # OTP رو توی لاگ چاپ کن
            # await self.sms_service.send_sms(phone_number, f"Your OTP code: {otp_code}")  # SMS رو غیرفعال کن
            logger.info(f"OTP sent to phone: {phone_number}")
            return {"message": "OTP sent successfully."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in send_otp for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error sending OTP.")

    def verify_otp(self, phone_number: str, otp_code: str) -> bool:
        """
        Verifies the provided OTP for the phone number.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in verify_otp.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")
            if not otp_code or len(otp_code) != 6 or not otp_code.isdigit():
                logger.error(f"Invalid OTP code format: {otp_code}")
                raise HTTPException(status_code=400, detail="OTP code must be a 6-digit number.")

            stored_otp = self.redis_service.get(f"otp:{phone_number}")
            if not stored_otp:
                logger.warning(f"No OTP found or expired for phone: {phone_number}")
                raise HTTPException(status_code=400, detail="OTP has expired or not found.")

            if stored_otp != otp_code:
                failed_attempts = self.redis_service.increment(f"otp_failed:{phone_number}")
                logger.warning(
                    f"Invalid OTP attempt {failed_attempts}/{self.OTP_MAX_ATTEMPTS} for phone: {phone_number}")

                if failed_attempts >= self.OTP_MAX_ATTEMPTS:
                    lock_duration = 600  # 10 minutes
                    self.redis_service.set_with_expiry(f"otp_locked:{phone_number}", "locked", lock_duration)
                    logger.error(f"Account {phone_number} locked for {lock_duration} seconds.")
                    raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts.")

                raise HTTPException(status_code=400, detail="Invalid OTP.")

            self.redis_service.delete(f"otp:{phone_number}")
            self.redis_service.delete(f"otp_failed:{phone_number}")
            logger.info(f"OTP verified successfully for phone: {phone_number}")
            return True
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_otp for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying OTP.")

    def is_account_locked(self, phone_number: str) -> bool:
        """
        Checks if the account is locked due to failed OTP attempts.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in is_account_locked.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            locked = self.redis_service.get(f"otp_locked:{phone_number}")
            result = bool(locked)
            if result:
                logger.warning(f"Account {phone_number} is currently locked.")
            return result
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in is_account_locked for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error checking account lock status.")