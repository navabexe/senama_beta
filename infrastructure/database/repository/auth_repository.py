# infrastructure/database/repository/auth_repository.py
import logging
from datetime import datetime, timezone
from typing import Optional, List
from bson import ObjectId
from fastapi import HTTPException
from infrastructure.database.client import DatabaseClient

logger = logging.getLogger(__name__)


class AuthRepository:
    """
    Manages database interactions for user authentication.
    """

    def __init__(self):
        try:
            self.db = DatabaseClient.get_database()
            self.users = self.db["users"]
            self.sessions = self.db["sessions"]
            logger.info("AuthRepository initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize AuthRepository: {str(e)}", exc_info=True)
            raise Exception("AuthRepository initialization failed.")

    async def get_user_by_phone(self, phone_number: str) -> Optional[dict]:
        """
        Retrieves a user by phone number from the database.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in get_user_by_phone.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            user = await self.users.find_one({"phone_number": phone_number})
            if user:
                logger.debug(f"User found for phone: {phone_number}")
            else:
                logger.debug(f"No user found for phone: {phone_number}")
            return user
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_user_by_phone for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving user.")

    async def create_user(self, phone_number: str) -> str:
        """
        Creates a new user in the database after OTP verification.
        """
        try:
            if not phone_number:
                logger.error("Phone number is empty in create_user.")
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")

            new_user = {
                "phone_number": phone_number,
                "status": "active",
                "role": "user",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            result = await self.users.insert_one(new_user)
            if not result.inserted_id:
                logger.error(f"Failed to insert user for phone: {phone_number}")
                raise HTTPException(status_code=500, detail="Failed to create user in database.")

            user_id = str(result.inserted_id)
            logger.info(f"User created with ID {user_id} for phone: {phone_number}")
            return user_id
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in create_user for {phone_number}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error creating user.")

    async def update_user_status(self, user_id: str, status: str):
        """
        Updates the status of a user in the database.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in update_user_status.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            if not status or status not in ["active", "blocked", "pending", "pending_deletion"]:
                logger.error(f"Invalid status: {status}")
                raise HTTPException(status_code=400, detail="Invalid user status.")

            result = await self.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}}
            )
            if result.matched_count == 0:
                logger.warning(f"No user found to update status for ID: {user_id}")
                raise HTTPException(status_code=404, detail="User not found.")

            logger.info(f"User status updated to {status} for ID: {user_id}")
        except HTTPException as e:
            raise e
        except ValueError as e:
            logger.error(f"Invalid user_id format: {user_id}, error: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid user ID format.")
        except Exception as e:
            logger.error(f"Unexpected error in update_user_status for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error updating user status.")

    async def store_session(self, user_id: str, session_id: str, device_info: dict):
        """
        Stores a new session for a user in the database.
        """
        try:
            if not user_id or not session_id or not device_info:
                logger.error("User ID, session ID, or device info is empty in store_session.")
                raise HTTPException(status_code=400, detail="User ID, session ID, and device info cannot be empty.")

            session_data = {
                "user_id": user_id,
                "session_id": session_id,
                "device_info": device_info,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            result = await self.sessions.insert_one(session_data)
            if not result.inserted_id:
                logger.error(f"Failed to store session {session_id} for user: {user_id}")
                raise HTTPException(status_code=500, detail="Failed to store session in database.")

            logger.debug(f"Stored session {session_id} for user: {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in store_session for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error storing session.")

    async def get_sessions_by_user(self, user_id: str) -> List[dict]:
        """
        Retrieves all sessions for a user from the database.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in get_sessions_by_user.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            sessions = await self.sessions.find({"user_id": user_id}).to_list(length=10)
            logger.debug(f"Retrieved {len(sessions)} sessions for user: {user_id}")
            return sessions
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_sessions_by_user for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving sessions.")

    async def delete_session(self, user_id: str, session_id: str):
        """
        Deletes a specific session for a user from the database.
        """
        try:
            if not user_id or not session_id:
                logger.error("User ID or session ID is empty in delete_session.")
                raise HTTPException(status_code=400, detail="User ID and session ID cannot be empty.")

            result = await self.sessions.delete_one({"user_id": user_id, "session_id": session_id})
            if result.deleted_count == 0:
                logger.warning(f"No session found to delete for user {user_id}, session {session_id}")
                raise HTTPException(status_code=404, detail="Session not found.")

            logger.debug(f"Deleted session {session_id} for user: {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in delete_session for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error deleting session.")

    async def delete_all_sessions(self, user_id: str):
        """
        Deletes all sessions for a user from the database.
        """
        try:
            if not user_id:
                logger.error("User ID is empty in delete_all_sessions.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")

            result = await self.sessions.delete_many({"user_id": user_id})
            logger.debug(f"Deleted {result.deleted_count} sessions for user: {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in delete_all_sessions for user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error deleting all sessions.")