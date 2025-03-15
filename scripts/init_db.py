import asyncio
import logging
from datetime import datetime, timezone
from fastapi import HTTPException
from infrastructure.database.client import DatabaseClient
from app.security.hashing import Hashing

logger = logging.getLogger(__name__)

async def initialize_database():
    """
    Initializes the database with default data, such as an admin user.
    """
    try:
        db = DatabaseClient.get_database()
        users_collection = db["users"]

        existing_admin = await users_collection.find_one({"role": "admin"})
        if existing_admin:
            logger.info("Admin user already exists, skipping initialization.")
            print("Admin user already exists.")
            return

        hashing = Hashing()
        admin_user = {
            "username": "admin",
            "password": hashing.hash_password("Admin@123"),
            "role": "admin",
            "status": "active",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        result = await users_collection.insert_one(admin_user)
        if not result.inserted_id:
            logger.error("Failed to insert admin user into database.")
            raise HTTPException(status_code=500, detail="Failed to create admin user.")

        logger.info("Admin user created successfully.")
        print("Admin user created successfully with ID:", str(result.inserted_id))
    except HTTPException as e:
        logger.error(f"HTTP error during database initialization: {str(e)}", exc_info=True)
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error initializing database.")

if __name__ == "__main__":
    try:
        asyncio.run(initialize_database())
    except Exception as e:
        logger.error(f"Failed to run database initialization: {str(e)}", exc_info=True)
        print(f"Error: {str(e)}")