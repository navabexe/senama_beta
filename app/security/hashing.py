# app/security/hashing.py
import logging
from fastapi import HTTPException
from passlib.context import CryptContext

logger = logging.getLogger(__name__)


class Hashing:
    """
    Manages hashing of sensitive data such as passwords.
    """

    def __init__(self):
        try:
            self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            logger.info("Hashing initialized with bcrypt scheme.")
        except Exception as e:
            logger.error(f"Failed to initialize Hashing: {str(e)}", exc_info=True)
            raise Exception("Hashing initialization failed.")

    def hash_password(self, password: str) -> str:
        """
        Hashes a password using bcrypt.
        """
        try:
            if not password:
                logger.error("Password is empty in hash_password.")
                raise HTTPException(status_code=400, detail="Password cannot be empty.")
            if not isinstance(password, str):
                logger.error(f"Invalid password type: {type(password)}")
                raise HTTPException(status_code=400, detail="Password must be a string.")

            hashed = self.pwd_context.hash(password)
            logger.debug("Password hashed successfully.")
            return hashed
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in hash_password: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error hashing password.")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifies a plain password against its hashed version.
        """
        try:
            if not plain_password or not hashed_password:
                logger.error("Plain password or hashed password is empty in verify_password.")
                raise HTTPException(status_code=400, detail="Password and hashed password cannot be empty.")
            if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
                logger.error(f"Invalid types - plain: {type(plain_password)}, hashed: {type(hashed_password)}")
                raise HTTPException(status_code=400, detail="Both passwords must be strings.")

            result = self.pwd_context.verify(plain_password, hashed_password)
            logger.debug(f"Password verification result: {result}")
            return result
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_password: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying password.")

    def hash_sensitive_data(self, data: str) -> str:
        """
        Hashes sensitive data (e.g., phone numbers) using bcrypt.
        """
        try:
            if not data:
                logger.error("Data is empty in hash_sensitive_data.")
                raise HTTPException(status_code=400, detail="Data cannot be empty.")
            if not isinstance(data, str):
                logger.error(f"Invalid data type: {type(data)}")
                raise HTTPException(status_code=400, detail="Data must be a string.")

            hashed = self.pwd_context.hash(data)
            logger.debug("Sensitive data hashed successfully.")
            return hashed
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in hash_sensitive_data: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error hashing sensitive data.")

    def verify_sensitive_data(self, data: str, hashed_data: str) -> bool:
        """
        Verifies sensitive data against its hashed version.
        """
        try:
            if not data or not hashed_data:
                logger.error("Data or hashed data is empty in verify_sensitive_data.")
                raise HTTPException(status_code=400, detail="Data and hashed data cannot be empty.")
            if not isinstance(data, str) or not isinstance(hashed_data, str):
                logger.error(f"Invalid types - data: {type(data)}, hashed: {type(hashed_data)}")
                raise HTTPException(status_code=400, detail="Both data must be strings.")

            result = self.pwd_context.verify(data, hashed_data)
            logger.debug(f"Sensitive data verification result: {result}")
            return result
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_sensitive_data: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying sensitive data.")