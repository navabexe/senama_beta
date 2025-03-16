import logging
from datetime import timedelta, datetime, timezone
from typing import Any

import redis
import json
from fastapi import HTTPException
from app.core.config import settings

logger = logging.getLogger(__name__)

class RedisService:
    def __init__(self, notification_service=None):
        self.notification_service = notification_service
        self.client = None
        try:
            redis_config = {
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
                "decode_responses": True,
                "socket_timeout": 5,  # اضافه کردن تایم‌اوت 5 ثانیه
                "socket_connect_timeout": 5
            }
            if settings.REDIS_USE_SSL:
                redis_config.update({
                    "ssl": True,
                    "ssl_ca_certs": settings.REDIS_SSL_CA_CERTS,
                    "ssl_certfile": settings.REDIS_SSL_CERT,
                    "ssl_keyfile": settings.REDIS_SSL_KEY
                })
            self.client = redis.StrictRedis(**redis_config)
            self.client.ping()
            logger.info(f"RedisService initialized successfully at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        except redis.ConnectionError as e:
            logger.warning(f"Failed to connect to Redis: {str(e)}. Running without Redis functionality.")
            self.client = None  # No Redis available, proceed without it

    def set_with_expiry(self, key: str, value: str, expiry_seconds: int):
        try:
            if not key or value is None:
                logger.error("Key or value is empty in set_with_expiry.")
                raise HTTPException(status_code=400, detail="Key and value cannot be empty.")
            if expiry_seconds <= 0:
                logger.error(f"Invalid expiry_seconds: {expiry_seconds}")
                raise HTTPException(status_code=400, detail="Expiry time must be positive.")
            if self.client:
                self.client.setex(key, expiry_seconds, value)
                logger.debug(f"Set key {key} with expiry {expiry_seconds} seconds.")
            else:
                logger.warning(f"Redis unavailable, skipping set_with_expiry for key {key}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in set_with_expiry for key {key}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error setting value in Redis.")

    def get(self, key: str) -> Any | None:
        try:
            if not key:
                logger.error("Key is empty in get.")
                raise HTTPException(status_code=400, detail="Key cannot be empty.")
            if self.client:
                value = self.client.get(key)
                logger.debug(f"Retrieved value for key {key}: {value}")
                return value
            else:
                logger.warning(f"Redis unavailable, returning None for key {key}")
                return None
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get for key {key}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving value from Redis.")

    def delete(self, key: str):
        try:
            if not key:
                logger.error("Key is empty in delete.")
                raise HTTPException(status_code=400, detail="Key cannot be empty.")
            if self.client:
                self.client.delete(key)
                logger.debug(f"Deleted key {key} from Redis.")
            else:
                logger.warning(f"Redis unavailable, skipping delete for key {key}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in delete for key {key}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error deleting key from Redis.")

    def increment(self, key: str) -> int:
        try:
            if not key:
                logger.error("Key is empty in increment.")
                raise HTTPException(status_code=400, detail="Key cannot be empty.")
            if self.client:
                value = self.client.incr(key)
                logger.debug(f"Incremented key {key} to {value}")
                return value
            else:
                logger.warning(f"Redis unavailable, returning 0 for increment on key {key}")
                return 0
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in increment for key {key}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error incrementing value in Redis.")

    def store_refresh_token(self, user_id: str, refresh_token: str):
        try:
            if not user_id or not refresh_token:
                logger.error("User ID or refresh token is empty in store_refresh_token.")
                raise HTTPException(status_code=400, detail="User ID and refresh token cannot be empty.")
            if self.client:
                key = f"refresh_tokens:{user_id}"
                self.client.sadd(key, refresh_token)
                self.client.expire(key, timedelta(days=7))
                logger.debug(f"Stored refresh token for user {user_id}")
            else:
                logger.warning(f"Redis unavailable, skipping store_refresh_token for user {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in store_refresh_token for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error storing refresh token.")

    def get_all_refresh_tokens(self, user_id: str) -> set:
        try:
            if not user_id:
                logger.error("User ID is empty in get_all_refresh_tokens.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if self.client:
                key = f"refresh_tokens:{user_id}"
                tokens = self.client.smembers(key) or set()
                logger.debug(f"Retrieved {len(tokens)} refresh tokens for user {user_id}")
                return tokens
            else:
                logger.warning(f"Redis unavailable, returning empty set for user {user_id}")
                return set()
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_all_refresh_tokens for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving refresh tokens.")

    def remove_refresh_token(self, user_id: str, refresh_token: str):
        try:
            if not user_id or not refresh_token:
                logger.error("User ID or refresh token is empty in remove_refresh_token.")
                raise HTTPException(status_code=400, detail="User ID and refresh token cannot be empty.")
            if self.client:
                key = f"refresh_tokens:{user_id}"
                self.client.srem(key, refresh_token)
                logger.debug(f"Removed refresh token for user {user_id}")
            else:
                logger.warning(f"Redis unavailable, skipping remove_refresh_token for user {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in remove_refresh_token for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error removing refresh token.")

    def delete_all_refresh_tokens(self, user_id: str):
        try:
            if not user_id:
                logger.error("User ID is empty in delete_all_refresh_tokens.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if self.client:
                key = f"refresh_tokens:{user_id}"
                self.client.delete(key)
                logger.debug(f"Deleted all refresh tokens for user {user_id}")
            else:
                logger.warning(f"Redis unavailable, skipping delete_all_refresh_tokens for user {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in delete_all_refresh_tokens for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error deleting refresh tokens.")

    def count_active_refresh_tokens(self, user_id: str) -> int:
        try:
            if not user_id:
                logger.error("User ID is empty in count_active_refresh_tokens.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if self.client:
                key = f"refresh_tokens:{user_id}"
                count = self.client.scard(key)
                logger.debug(f"Counted {count} active refresh tokens for user {user_id}")
                return count
            else:
                logger.warning(f"Redis unavailable, returning 0 for active refresh tokens for user {user_id}")
                return 0
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in count_active_refresh_tokens for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error counting refresh tokens.")

    def get_user_sessions(self, user_id: str) -> dict:
        try:
            if not user_id:
                logger.error("User ID is empty in get_user_sessions.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if self.client:
                session_keys = self.client.keys(f"session:{user_id}:*")
                sessions = {}
                for key in session_keys:
                    value = self.client.get(key)
                    if value:
                        sessions[key] = json.loads(value)
                    else:
                        logger.warning(f"Empty value for session key {key}")
                logger.debug(f"Retrieved {len(sessions)} sessions for user {user_id}")
                return sessions
            else:
                logger.warning(f"Redis unavailable, returning empty dict for user {user_id}")
                return {}
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_user_sessions for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving sessions.")

    def delete_session(self, user_id: str, session_id: str):
        try:
            if not user_id or not session_id:
                logger.error("User ID or session ID is empty in delete_session.")
                raise HTTPException(status_code=400, detail="User ID and session ID cannot be empty.")
            if self.client:
                key = f"session:{user_id}:{session_id}"
                self.client.delete(key)
                logger.debug(f"Deleted session {session_id} for user {user_id}")
            else:
                logger.warning(f"Redis unavailable, skipping delete_session for user {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in delete_session for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error deleting session.")

    def delete_all_sessions(self, user_id: str):
        try:
            if not user_id:
                logger.error("User ID is empty in delete_all_sessions.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if self.client:
                session_keys = self.client.keys(f"session:{user_id}:*")
                if session_keys:
                    for key in session_keys:
                        self.client.delete(key)
                    logger.debug(f"Deleted {len(session_keys)} sessions for user: {user_id}")
                else:
                    logger.debug(f"No sessions found to delete for user: {user_id}")
            else:
                logger.warning(f"Redis unavailable, skipping delete_all_sessions for user {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in delete_all_sessions for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error deleting all sessions.")

    async def store_session(self, user_id: str, session_id: str, device_info: dict, expiry_hours: int = 24):
        try:
            if not user_id or not session_id or not device_info:
                logger.error("User ID, session ID, or device info is empty in store_session.")
                raise HTTPException(status_code=400, detail="User ID, session ID, and device info cannot be empty.")
            if expiry_hours <= 0:
                logger.error(f"Invalid expiry_hours: {expiry_hours}")
                raise HTTPException(status_code=400, detail="Expiry hours must be positive.")

            if self.client:
                current_sessions = self.get_user_sessions(user_id)
                if len(current_sessions) >= 10:
                    oldest_key = min(current_sessions.keys(), key=lambda k: current_sessions[k]["created_at"])
                    self.delete_session(user_id, oldest_key.split(":")[-1])
                    if self.notification_service:
                        await self.notification_service.send_notification(
                            user_id, "Session Limit Reached", "Oldest session terminated due to new login."
                        )
                    logger.info(f"Removed oldest session for user {user_id} due to limit.")

                key = f"session:{user_id}:{session_id}"
                device_info["created_at"] = datetime.now(timezone.utc).isoformat()
                self.client.setex(key, timedelta(hours=expiry_hours), json.dumps(device_info))
                logger.debug(f"Stored session {session_id} for user {user_id}")
            else:
                logger.warning(f"Redis unavailable, skipping store_session for user {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in store_session for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error storing session.")