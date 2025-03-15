# app/security/otp.py
import random
import logging
from fastapi import HTTPException
from infrastructure.caching.redis_service import RedisService
from app.core.config import settings

logger = logging.getLogger(__name__)


class OTPManager:
    """
    Manages OTP generation, storage, and verification.
    """

    def __init__(self):
        try:
            self.redis_service = RedisService()
            self.OTP_EXPIRATION_MINUTES = settings.OTP_EXPIRE_MINUTES
            self.OTP_MAX_ATTEMPTS = 5
            self.OTP_COOLDOWN_SECONDS = 60
            logger.info("OTPManager initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize OTPManager: {str(e)}", exc_info=True)
            raise Exception("OTPManager initialization failed.")

    def generate_otp(self, phone_number: str, device_info: dict = None) -> str:
        """
        Generates and stores an OTP for a phone number with dynamic expiration based on device.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in generate_otp.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            last_request = self.redis_service.get(f"otp_cooldown:{phone_number}")
            if last_request:
                logger.warning(f"Cooldown active for phone: {phone_number}")
                raise HTTPException(status_code=429,
                                    detail=f"Please wait {self.OTP_COOLDOWN_SECONDS} seconds before requesting again.")

            otp_code = str(random.randint(100000, 999999))
            expiry_seconds = (5 * 60) if self.is_known_device(phone_number, device_info) else (2 * 60)
            self.redis_service.set_with_expiry(f"otp:{phone_number}", otp_code, expiry_seconds)
            self.redis_service.set_with_expiry(f"otp_cooldown:{phone_number}", "1", self.OTP_COOLDOWN_SECONDS)

            logger.info(f"OTP generated for phone: {phone_number}, expires in {expiry_seconds} seconds.")
            return otp_code
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in generate_otp for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error generating OTP.")

    def verify_otp(self, phone_number: str, otp_code: str) -> bool:
        """
        Verifies an OTP and enforces security measures like account locking.
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
                    lock_count = self.redis_service.increment(f"lock_count:{phone_number}")
                    lock_duration = 600  # 10 minutes default lock
                    if lock_count >= 3:
                        lock_duration = 24 * 3600  # 24 hours lock after 3 lockouts
                        self.notification_service.send_notification(
                            "admin", "Account Locked",
                            f"Account {phone_number} locked for 24 hours due to repeated failed attempts."
                        )
                    self.redis_service.set_with_expiry(f"otp_locked:{phone_number}", "locked", lock_duration)
                    logger.error(f"Account {phone_number} locked for {lock_duration} seconds.")
                    raise HTTPException(status_code=403,
                                        detail=f"Account locked for {lock_duration // 60} minutes due to too many failed attempts.")

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

    def is_known_device(self, phone_number: str, device_info: dict) -> bool:
        """
        Checks if the device is known based on stored device info.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in is_known_device.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")
            if not device_info:
                logger.info(f"No device info provided for phone: {phone_number}, treating as unknown.")
                return False

            known_devices = self.redis_service.get(f"known_devices:{phone_number}")
            if not known_devices:
                logger.info(f"No known devices found for phone: {phone_number}")
                return False

            import json
            known_devices_list = json.loads(known_devices)
            if not isinstance(known_devices_list, list):
                logger.error(f"Invalid known devices format for phone: {phone_number}: {known_devices}")
                raise HTTPException(status_code=500, detail="Internal server error: Invalid device data format.")

            device_str = json.dumps(device_info, sort_keys=True)
            result = device_str in [json.dumps(d, sort_keys=True) for d in known_devices_list]
            logger.info(f"Device check for phone {phone_number}: {'known' if result else 'unknown'}")
            return result
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in is_known_device for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error checking device status.")

    def is_account_locked(self, phone_number: str) -> bool:
        """
        Checks if the account is currently locked due to failed OTP attempts.
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