# scripts/cleanup.py
import asyncio
import logging
from fastapi import HTTPException
from infrastructure.database.client import DatabaseClient
from infrastructure.caching.redis_service import RedisService
from infrastructure.external.notification_service import NotificationService

logger = logging.getLogger(__name__)


async def cleanup_deleted_accounts():
    """
    Cleans up accounts marked for deletion after their pending period expires.
    """
    try:
        db = DatabaseClient.get_database()
        users_collection = db["users"]
        redis_service = RedisService()
        notification_service = NotificationService()

        expired_deletions = redis_service.client.keys("deletion:*")
        if not expired_deletions:
            logger.info("No accounts pending deletion found.")
            print("No accounts pending deletion.")
            return

        for key in expired_deletions:
            phone_number = key.split(":")[1]
            try:
                user = await users_collection.find_one({"phone_number": phone_number})
                if not user or user.get("status") != "pending_deletion":
                    logger.warning(f"No pending deletion user found for phone: {phone_number}")
                    redis_service.delete(key)
                    continue

                result = await users_collection.delete_one({"phone_number": phone_number})
                if result.deleted_count == 0:
                    logger.error(f"Failed to delete user with phone: {phone_number}")
                    raise HTTPException(status_code=500, detail=f"Failed to delete user {phone_number}.")

                redis_service.delete(key)
                await notification_service.send_notification(
                    phone_number, "Account Deleted", "Your account has been successfully deleted."
                )
                logger.info(f"Account deleted for phone: {phone_number}")
                print(f"Deleted account for phone: {phone_number}")
            except HTTPException as e:
                logger.error(f"HTTP error during cleanup for {phone_number}: {str(e)}", exc_info=True)
                raise e
            except Exception as e:
                logger.error(f"Unexpected error during cleanup for {phone_number}: {str(e)}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Error cleaning up account {phone_number}.")

        logger.info(f"Cleanup completed. Processed {len(expired_deletions)} accounts.")
        print(f"Cleanup completed. Processed {len(expired_deletions)} accounts.")
    except HTTPException as e:
        logger.error(f"HTTP error during cleanup: {str(e)}", exc_info=True)
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during cleanup: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during cleanup.")


if __name__ == "__main__":
    try:
        asyncio.run(cleanup_deleted_accounts())
    except Exception as e:
        logger.error(f"Failed to run cleanup script: {str(e)}", exc_info=True)
        print(f"Error: {str(e)}")