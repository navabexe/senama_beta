import logging
from infrastructure.database.client import DatabaseClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    client = DatabaseClient.get_client()
    logger.info("Connected to MongoDB successfully!")
    client.server_info()  # تست واقعی اتصال
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}", exc_info=True)