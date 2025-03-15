# infrastructure/caching/blacklist.py
import logging
from datetime import timedelta
import redis
from fastapi import HTTPException
from app.core.config import settings

logger = logging.getLogger(__name__)


class BlacklistService:
    """
    Manages a blacklist of expired or invalidated tokens in Redis.
    """

    def __init__(self):
        try:
            redis_config = {
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": 1,  # Use a separate DB for blacklist
                "decode_responses": True
            }
            if settings.REDIS_USE_SSL:
                redis_config.update({
                    "ssl": True,
                    "ssl_ca_certs": settings.REDIS_SSL_CA_CERTS,
                    "ssl_certfile": settings.REDIS_SSL_CERT,
                    "ssl_keyfile": settings.REDIS_SSL_KEY
                })
            self.client = redis.StrictRedis(**redis_config)
            # Test connection
            self.client.ping()
            self.DEFAULT_EXPIRY_MINUTES = 30
            logger.info(f"BlacklistService initialized successfully at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis for blacklist: {str(e)}", exc_info=True)
            raise Exception(f"Redis connection failed for blacklist: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to initialize BlacklistService: {str(e)}", exc_info=True)
            raise Exception("BlacklistService initialization failed.")

    def add_to_blacklist(self, token: str, expiry_minutes: int = None):
        """
        Adds a token to the blacklist with a specified expiration time.
        """
        try:
            if not token:
                logger.error("Token is empty in add_to_blacklist.")
                raise HTTPException(status_code=400, detail="Token cannot be empty.")
            if expiry_minutes is not None and expiry_minutes <= 0:
                logger.error(f"Invalid expiry_minutes: {expiry_minutes}")
                raise HTTPException(status_code=400, detail="Expiry minutes must be positive.")

            expiry = expiry_minutes if expiry_minutes is not None else self.DEFAULT_EXPIRY_MINUTES
            key = f"blacklist:{token}"
            self.client.setex(key, timedelta(minutes=expiry), "blacklisted")
            logger.debug(f"Added token to blacklist with key {key}, expires in {expiry} minutes.")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in add_to_blacklist for token {token}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error adding token to blacklist.")

    def is_blacklisted(self, token: str) -> bool:
        """
        Checks if a token is in the blacklist.
        """
        try:
            if not token:
                logger.error("Token is empty in is_blacklisted.")
                raise HTTPException(status_code=400, detail="Token cannot be empty.")

            key = f"blacklist:{token}"
            exists = self.client.exists(key) > 0
            if exists:
                logger.debug(f"Token {token} is blacklisted.")
            return exists
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in is_blacklisted for token {token}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error checking blacklist status.")