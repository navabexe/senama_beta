# infrastructure/database/repository/auth_repository.py
import logging
from datetime import datetime, timezone
from typing import Optional, List

import pymongo
from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorCollection

logger = logging.getLogger(__name__)


class AuthRepository:
    def __init__(self):
        from infrastructure.database.client import DatabaseClient
        self.db = DatabaseClient.get_database()
        self.users: AsyncIOMotorCollection = self.db["users"]


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

    def _normalize_phone(self, phone_number: str) -> str:
        """Normalize phone number by removing spaces and dashes."""
        return phone_number.replace(" ", "").replace("-", "")

    async def get_user_by_username(self, username: str) -> Optional[dict]:
        """
        Retrieves a user by username from the database.
        """
        try:
            if not username:
                logger.error("Username is empty in get_user_by_username.")
                raise HTTPException(status_code=400, detail="Username cannot be empty.")
            user = await self.users.find_one({"username": username})
            if user:
                logger.debug(f"User found for username: {username}")
            else:
                logger.debug(f"No user found for username: {username}")
            return user
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_user_by_username for {username}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving user.")

    async def update_user_status(self, user_id: str, status: str):
        """
        Updates the status of a user in the database.
        """
        try:
            if not user_id or not status:
                logger.error(f"User ID or status is empty in update_user_status. user_id: {user_id}, status: {status}")
                raise HTTPException(status_code=400, detail="User ID and status cannot be empty.")
            result = await self.users.update_one(
                {"_id": user_id},
                {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}}
            )
            if result.modified_count == 0:
                logger.warning(f"No user updated for user_id: {user_id}")
                raise HTTPException(status_code=404, detail="User not found or status not changed.")
            logger.info(f"User status updated to {status} for ID: {user_id}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in update_user_status for {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error updating user status.")

    async def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """
        Retrieves a user by ID from the database.
        """
        try:
            from bson.objectid import ObjectId
            if not user_id:
                logger.error("User ID is empty in get_user_by_id.")
                raise HTTPException(status_code=400, detail="User ID cannot be empty.")
            try:
                oid = ObjectId(user_id)
                user = await self.users.find_one({"_id": oid})
                if user:
                    logger.debug(f"User found for ID: {user_id}")
                    return user
                else:
                    logger.debug(f"No user found for ID: {user_id}")
                    raise HTTPException(status_code=404, detail="User not found.")
            except ValueError:
                logger.warning(f"Invalid ObjectId format for user_id: {user_id}")
                raise HTTPException(status_code=404, detail="User not found (invalid ID format).")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_user_by_id for {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving user.")

    async def get_user_by_phone(self, phone_number: str) -> Optional[dict]:
        try:
            normalized_phone = self._normalize_phone(phone_number)
            if not normalized_phone:
                raise HTTPException(status_code=400, detail="Phone number cannot be empty.")
            user = await self.users.find_one({"phone_number": normalized_phone})
            logger.debug(f"User lookup for phone {normalized_phone}: {user}")
            return user
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected error in get_user_by_phone: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error retrieving user.")

    async def create_user(self, phone_number: str, role: str = "user") -> str:
        normalized_phone = self._normalize_phone(phone_number)
        if not normalized_phone or not role:
            raise HTTPException(status_code=400, detail="Phone number and role cannot be empty.")

        existing_user = await self.users.find_one({"phone_number": normalized_phone})
        if existing_user:
            current_roles = existing_user.get("roles", [])
            if role not in current_roles:
                current_roles.append(role)
                await self.users.update_one(
                    {"_id": existing_user["_id"]},
                    {"$set": {"roles": current_roles, "updated_at": datetime.now(timezone.utc)}}
                )
                logger.info(f"Role {role} added to existing user: {normalized_phone}")
            return str(existing_user["_id"])

        user = {
            "phone_number": normalized_phone,
            "roles": [role],
            "status": "active",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        result = await self.users.insert_one(user)
        logger.info(f"User created with ID {result.inserted_id} for phone: {normalized_phone} with role: {role}")
        return str(result.inserted_id)