import logging
from infrastructure.caching.redis_service import RedisService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    redis_service = RedisService()
    redis_service.client.ping()  # تست اتصال
    logger.info("Connected to Redis successfully!")
except Exception as e:
    logger.error(f"Failed to connect to Redis: {str(e)}", exc_info=True)