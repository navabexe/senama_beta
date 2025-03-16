import logging
from typing import Optional
from fastapi import HTTPException
from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
import os

logger = logging.getLogger(__name__)

# Load environment variables from .env file
try:
    load_dotenv()
    logger.info("Environment variables loaded from .env file.")
except Exception as e:
    logger.error(f"Failed to load .env file: {str(e)}", exc_info=True)
    raise Exception("Unable to load environment variables.")

class Settings(BaseSettings):
    """
    Application configuration settings loaded from environment variables.
    """
    # MongoDB Settings
    MONGO_URI: str = Field(..., description="MongoDB connection URI")
    MONGO_DB: str = Field(..., description="MongoDB database name")

    # JWT Settings
    SECRET_KEY: str = Field(..., min_length=32, description="Secret key for JWT access token encoding")
    REFRESH_SECRET_KEY: str = Field(..., min_length=32, description="Secret key for JWT refresh token encoding")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, ge=1, description="Access token expiration time in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, ge=1, description="Refresh token expiration time in days")
    ALGORITHM: str = Field("HS512", description="JWT encoding algorithm")

    # OTP Settings
    OTP_EXPIRE_MINUTES: int = Field(10, ge=1, description="OTP expiration time in minutes")
    SMS_PANEL_KEY: str = Field(..., description="API key for SMS provider (e.g., Kavenegar)")

    # Redis Settings
    REDIS_HOST: str = Field("localhost", description="Redis host address")
    REDIS_PORT: int = Field(6379, ge=1, le=65535, description="Redis port number")
    REDIS_DB: int = Field(0, ge=0, le=15, description="Redis database number")
    REDIS_USE_SSL: bool = Field(False, description="Enable SSL for Redis connection")
    REDIS_SSL_CA_CERTS: Optional[str] = Field(None, description="Path to Redis SSL CA certificate")
    REDIS_SSL_CERT: Optional[str] = Field(None, description="Path to Redis SSL certificate")
    REDIS_SSL_KEY: Optional[str] = Field(None, description="Path to Redis SSL private key")

    # SSL Settings for HTTPS
    SSL_CERT_FILE: Optional[str] = Field(None, description="Path to SSL certificate file for HTTPS")
    SSL_KEY_FILE: Optional[str] = Field(None, description="Path to SSL private key file for HTTPS")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=False
    )


    def __init__(self, **values):
        try:
            super().__init__(**values)
            self._validate_paths()
            logger.info("Settings initialized successfully.")
            logger.debug(
                f"Loaded settings: MONGO_URI={self.MONGO_URI}, "
                f"REDIS_HOST={self.REDIS_HOST}, SECRET_KEY={'*' * 8} (hidden)"
            )
        except ValidationError as e:
            logger.error(f"Validation error in Settings: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Invalid configuration: {str(e)}")
        except ValueError as e:
            logger.error(f"Path validation error: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error initializing Settings: {str(e)}", exc_info=True)
            raise Exception("Failed to initialize application settings.")

    def _validate_paths(self):
        """
        Validate file paths for SSL certificates and keys.
        """
        paths = [
            ("REDIS_SSL_CA_CERTS", self.REDIS_SSL_CA_CERTS),
            ("REDIS_SSL_CERT", self.REDIS_SSL_CERT),
            ("REDIS_SSL_KEY", self.REDIS_SSL_KEY),
            ("SSL_CERT_FILE", self.SSL_CERT_FILE),
            ("SSL_KEY_FILE", self.SSL_KEY_FILE)
        ]
        for name, path in paths:
            if path and not os.path.isfile(path):
                logger.error(f"Invalid file path for {name}: {path}")
                raise ValueError(f"File not found for {name}: {path}")

# Singleton instance of Settings
try:
    settings = Settings()
except Exception as e:
    logger.error(f"Failed to create Settings instance: {str(e)}", exc_info=True)
    raise Exception("Application configuration failed to load.")