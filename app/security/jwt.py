# app/security/jwt.py
from datetime import datetime, timedelta, timezone
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from fastapi import HTTPException
from app.core.config import settings
from infrastructure.caching.blacklist import BlacklistService
import logging

logger = logging.getLogger(__name__)

# Constants from settings
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS


class JWTManager:
    """
    Manages the creation and validation of JWT tokens.
    """

    def __init__(self):
        try:
            self.blacklist_service = BlacklistService()
            logger.info("JWTManager initialized with BlacklistService.")
        except Exception as e:
            logger.error(f"Failed to initialize BlacklistService in JWTManager: {str(e)}", exc_info=True)
            raise Exception("JWTManager initialization failed.")

    @staticmethod
    def create_access_token(user_id: str, roles: list[str]) -> str:
        """
        Creates an access token with a configurable expiration time.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in create_access_token.")
                raise ValueError("User ID cannot be empty.")
            if not isinstance(roles, list):
                logger.error(f"Invalid roles format: {roles}")
                raise ValueError("Roles must be a list.")

            payload = {
                "sub": user_id,
                "roles": roles,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
                "iat": datetime.now(timezone.utc),
                "token_type": "access"
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
            logger.info(f"Access token created for user: {user_id}")
            return token
        except ValueError as e:
            logger.error(f"Validation error in create_access_token: {str(e)}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error in create_access_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error creating access token.")

    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """
        Creates a refresh token with a configurable expiration time.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in create_refresh_token.")
                raise ValueError("User ID cannot be empty.")

            payload = {
                "sub": user_id,
                "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
                "iat": datetime.now(timezone.utc),
                "token_type": "refresh"
            }
            token = jwt.encode(payload, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
            logger.info(f"Refresh token created for user: {user_id}")
            return token
        except ValueError as e:
            logger.error(f"Validation error in create_refresh_token: {str(e)}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error in create_refresh_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error creating refresh token.")

    def verify_token(self, token: str, token_type: str) -> dict:
        """
        Verifies a JWT token and checks if it is blacklisted.
        """
        try:
            if not token:
                logger.error("Token is empty in verify_token.")
                raise HTTPException(status_code=401, detail="Token cannot be empty.")
            if token_type not in ["access", "refresh"]:
                logger.error(f"Invalid token_type: {token_type}")
                raise HTTPException(status_code=400, detail="Invalid token type specified.")

            secret_key = settings.SECRET_KEY if token_type == "access" else settings.REFRESH_SECRET_KEY
            payload = jwt.decode(token, secret_key, algorithms=[settings.ALGORITHM])
            if payload.get("token_type") != token_type:
                logger.error(f"Token type mismatch: expected {token_type}, got {payload.get('token_type')}")
                raise HTTPException(status_code=403, detail="Invalid token type.")

            if self.blacklist_service.is_blacklisted(token):
                logger.warning(f"Blacklisted token used: {token}")
                raise HTTPException(status_code=403, detail="This token has been blacklisted.")

            logger.info(f"Token verified successfully: {token_type}")
            return payload
        except ExpiredSignatureError:
            logger.warning(f"Expired token: {token}")
            raise HTTPException(status_code=401, detail="Token has expired.")
        except InvalidTokenError:
            logger.error(f"Invalid token: {token}")
            raise HTTPException(status_code=401, detail="Invalid token.")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying token.")

    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Generates a new access token using a refresh token.
        """
        try:
            if not refresh_token:
                logger.error("Refresh token is empty in refresh_access_token.")
                raise HTTPException(status_code=400, detail="Refresh token cannot be empty.")

            payload = self.verify_token(refresh_token, "refresh")
            user_id = payload.get("sub")
            if not user_id:
                logger.error("No user_id found in refresh token payload.")
                raise HTTPException(status_code=400, detail="Invalid refresh token payload.")

            self.blacklist_service.add_to_blacklist(refresh_token)
            new_access_token = self.create_access_token(user_id, payload.get("roles", []))
            new_refresh_token = self.create_refresh_token(user_id)

            logger.info(f"Access token refreshed for user: {user_id}")
            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token
            }
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in refresh_access_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error refreshing token.")