# infrastructure/database/client.py
import logging
import motor.motor_asyncio
from fastapi import HTTPException
from app.core.config import settings

logger = logging.getLogger(__name__)


class DatabaseClient:
    """
    Manages the connection to MongoDB database.
    """
    _client: motor.motor_asyncio.AsyncIOMotorClient = None
    _database: motor.motor_asyncio.AsyncIOMotorDatabase = None

    @classmethod
    def get_client(cls) -> motor.motor_asyncio.AsyncIOMotorClient:
        """
        Retrieves or initializes the MongoDB client.
        """
        try:
            if cls._client is None:
                cls._client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGO_URI)
                # Test connection
                cls._client.server_info()
                logger.info(f"MongoDB client initialized successfully at {settings.MONGO_URI}")
            return cls._client
        except motor.motor_asyncio.exceptions.ConnectionError as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"MongoDB connection failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error initializing MongoDB client: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error initializing MongoDB client.")

    @classmethod
    def get_database(cls, db_name: str = settings.MONGO_DB) -> motor.motor_asyncio.AsyncIOMotorDatabase:
        """
        Retrieves or initializes the MongoDB database instance.
        """
        try:
            if not db_name:
                logger.error("Database name is empty in get_database.")
                raise HTTPException(status_code=400, detail="Database name cannot be empty.")

            if cls._database is None:
                client = cls.get_client()
                cls._database = client[db_name]
                logger.info(f"MongoDB database '{db_name}' initialized successfully.")
            return cls._database
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error initializing MongoDB database {db_name}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error initializing MongoDB database.")