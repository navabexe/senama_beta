# app/services/auth/token_service.py
import logging
from fastapi import HTTPException
from app.security.jwt import JWTManager
from infrastructure.caching.blacklist import BlacklistService
from infrastructure.caching.redis_service import RedisService

logger = logging.getLogger(__name__)


class TokenService:
    """
    Manages the creation, validation, and refresh of authentication tokens.
    """

    def __init__(self):
        try:
            self.jwt_manager = JWTManager()
            self.blacklist_service = BlacklistService()
            self.redis_service = RedisService()
            self.MAX_REFRESH_TOKENS = 3
            logger.info("TokenService initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize TokenService: {str(e)}", exc_info=True)
            raise Exception("TokenService initialization failed.")

    def create_tokens(self, user_id: str, roles: list[str] = ["user"]) -> dict:
        """
        Creates access and refresh tokens for a user.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in create_tokens.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if not isinstance(roles, list):
                logger.error(f"Invalid roles format: {roles}")
                raise HTTPException(status_code=400, detail="Roles must be a list.")

            access_token = self.jwt_manager.create_access_token(user_id, roles)
            refresh_token = self.jwt_manager.create_refresh_token(user_id)
            self.store_refresh_token(user_id, refresh_token)

            logger.info(f"Tokens created for user: {user_id}")
            return {"access_token": access_token, "refresh_token": refresh_token}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in create_tokens for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error creating tokens.")

    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Refreshes an access token using a refresh token, with security checks.
        """
        try:
            if not refresh_token:
                logger.error("Refresh token is empty in refresh_access_token.")
                raise HTTPException(status_code=400, detail="Refresh token cannot be empty.")

            if self.blacklist_service.is_blacklisted(refresh_token):
                user_id = self.jwt_manager.verify_token(refresh_token, "refresh").get("sub")
                self.redis_service.set_with_expiry(f"account_locked:{user_id}", "locked", 24 * 3600)
                self.notification_service.send_notification(
                    user_id, "Account Locked", "Unauthorized use of refresh token detected."
                )
                logger.error(f"Blacklisted refresh token used by user: {user_id}")
                raise HTTPException(status_code=403, detail="This refresh token is no longer valid.")

            payload = self.jwt_manager.verify_token(refresh_token, "refresh")
            user_id = payload.get("sub")
            if not user_id:
                logger.error("No user_id found in refresh token payload.")
                raise HTTPException(status_code=400, detail="Invalid refresh token payload.")

            if self.redis_service.count_active_refresh_tokens(user_id) >= self.MAX_REFRESH_TOKENS:
                logger.warning(f"Maximum refresh tokens exceeded for user: {user_id}")
                raise HTTPException(status_code=403, detail="Maximum number of refresh tokens reached.")

            self.blacklist_service.add_to_blacklist(refresh_token)
            self.redis_service.remove_refresh_token(user_id, refresh_token)
            new_tokens = self.create_tokens(user_id, payload.get("roles", ["user"]))

            logger.info(f"Access token refreshed for user: {user_id}")
            return new_tokens
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in refresh_access_token: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error refreshing token.")

    def store_refresh_token(self, user_id: str, refresh_token: str):
        """
        Stores a refresh token in Redis with a limit on active tokens.
        """
        try:
            if not user_id or not refresh_token:
                logger.error("User ID or refresh token is empty in store_refresh_token.")
                raise HTTPException(status_code=400, detail="User ID and refresh token cannot be empty.")

            key = f"refresh_tokens:{user_id}"
            current_tokens = self.redis_service.get_all_refresh_tokens(user_id)
            if len(current_tokens) >= self.MAX_REFRESH_TOKENS:
                oldest_token = current_tokens.pop()
                self.blacklist_service.add_to_blacklist(oldest_token)
                self.redis_service.remove_refresh_token(user_id, oldest_token)
                logger.info(f"Oldest refresh token removed for user: {user_id}")

            self.redis_service.store_refresh_token(user_id, refresh_token)
            logger.info(f"Refresh token stored for user: {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in store_refresh_token for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error storing refresh token.")

    def invalidate_user_tokens(self, user_id: str) -> dict:
        """
        Invalidates all refresh tokens for a user.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in invalidate_user_tokens.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            active_tokens = self.redis_service.get_all_refresh_tokens(user_id)
            for token in active_tokens:
                self.blacklist_service.add_to_blacklist(token)
            self.redis_service.delete_all_refresh_tokens(user_id)

            logger.info(f"All tokens invalidated for user: {user_id}")
            return {"message": "All user tokens invalidated."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in invalidate_user_tokens for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error invalidating tokens.")

    def force_logout(self, user_id: str) -> dict:
        """
        Forces logout of all sessions and tokens for a user by admin.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in force_logout.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            self.invalidate_user_tokens(user_id)
            self.redis_service.delete_all_sessions(user_id)
            logger.info(f"Forced logout completed for user: {user_id}")
            return {"message": "All sessions and tokens terminated."}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in force_logout for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error during force logout.")