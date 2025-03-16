# scripts/init_db.py
import asyncio
import logging
from datetime import datetime, timezone
from fastapi import HTTPException
from infrastructure.database.client import DatabaseClient
from app.security.hashing import Hashing

logger = logging.getLogger(__name__)


async def initialize_database():
    db = DatabaseClient.get_database()
    users_collection = db["users"]
    await users_collection.create_index([("phone_number", 1)], unique=True)
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
    logger.info("Admin user created successfully.")
    print("Admin user created successfully with ID:", str(result.inserted_id))


if __name__ == "__main__":
    try:
        asyncio.run(initialize_database())
    except Exception as e:
        logger.error(f"Failed to run database initialization: {str(e)}", exc_info=True)
        print(f"Error: {str(e)}")