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
            logger.info(f"JWTManager initialized with SECRET_KEY: {settings.SECRET_KEY[:8]}...")
        except Exception as e:
            logger.error(f"Failed to initialize BlacklistService in JWTManager: {str(e)}", exc_info=True)
            raise Exception("JWTManager initialization failed.")

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
            # Use phone_number from original payload if available, or fetch from DB if needed
            phone_number = payload.get("phone_number", "unknown")
            new_access_token = self.create_access_token(user_id, payload.get("roles", []), phone_number)
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
            logger.debug(f"Verifying token with secret_key: {secret_key[:8]}... (hidden)")
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
        except InvalidTokenError as e:
            logger.error(f"Invalid token: {token}, error: {str(e)}")
            raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in verify_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error verifying token.")

    # app/security/jwt.py
    @staticmethod
    def create_access_token(user_id: str, roles: list[str], phone_number: str, temp: bool = False) -> str:
        """
        Creates an access token with configurable expiration time and additional claims.
        """
        try:
            if not user_id or not phone_number or not roles:
                logger.error("User ID, phone number, or roles are empty in create_access_token.")
                raise ValueError("User ID, phone number, and roles cannot be empty.")
            if not isinstance(roles, list):
                logger.error(f"Invalid roles format: {roles}")
                raise ValueError("Roles must be a list.")

            from datetime import datetime, timezone
            import uuid
            now = datetime.now(timezone.utc)
            payload = {
                "sub": user_id,
                "roles": roles,  # اضافه کردن roles به ریشه توکن
                "user": {
                    "id": user_id,
                    "phone_number": phone_number,
                    "roles": roles,
                    "created_at": now.isoformat()
                },
                "iss": "marketplace-auth",
                "jti": str(uuid.uuid4()),
                "scope": "read:profile",
                "amr": ["otp"],
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
                "token_type": "access"
            }
            if temp:
                payload["temp"] = True

            token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
            logger.info(f"Access token created for user: {user_id}, phone: {phone_number}, temp: {temp}")
            return token
        except ValueError as e:
            logger.error(f"Validation error in create_access_token: {str(e)}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error in create_access_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error creating access token.")