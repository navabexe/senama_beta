from fastapi import HTTPException, Request, Depends
from typing import List
from app.security.jwt import JWTManager
import logging

logger = logging.getLogger(__name__)


def get_jwt_manager():
    return JWTManager()

# app/middleware/rbac.py
async def role_based_access_control(request: Request, required_roles: List[str], jwt_manager: JWTManager = Depends(get_jwt_manager)):
    try:
        token = request.headers.get("Authorization")
        if not token:
            logger.error("No Authorization header provided.")
            raise HTTPException(status_code=401, detail="Authorization header missing.")

        if not token.startswith("Bearer "):
            logger.error("Invalid token format: Bearer prefix missing.")
            raise HTTPException(status_code=401, detail="Invalid token format. Use 'Bearer <token>'.")

        token = token.split(" ")[1]
        if not token:
            logger.error("Token is empty after splitting.")
            raise HTTPException(status_code=401, detail="Token is empty.")

        logger.debug(f"Attempting to verify token: {token[:20]}...")
        payload = jwt_manager.verify_token(token, "access")
        logger.debug(f"Token payload: {payload}")
        user_roles = payload.get("roles", [])

        if not isinstance(user_roles, list):
            logger.error(f"Invalid roles format in token: {user_roles}")
            raise HTTPException(status_code=500, detail="Internal server error: Invalid roles format in token.")

        if not any(role in user_roles for role in required_roles):
            logger.warning(f"User lacks required roles. Required: {required_roles}, Found: {user_roles}")
            raise HTTPException(status_code=403, detail="Unauthorized: Required role not found.")

        logger.info(f"RBAC check passed for roles: {required_roles}")
        return True
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error in RBAC middleware: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during role validation.")

async def permission_based_access_control(request: Request, required_permissions: List[str]):
    """
    Middleware to enforce permission-based access control.
    Verifies if the user has the required permissions based on roles in JWT token.
    """
    try:
        token = request.headers.get("Authorization")
        if not token:
            logger.error("No Authorization header provided.")
            raise HTTPException(status_code=401, detail="Authorization header missing.")

        if not token.startswith("Bearer "):
            logger.error("Invalid token format: Bearer prefix missing.")
            raise HTTPException(status_code=401, detail="Invalid token format. Use 'Bearer <token>'.")

        token = token.split(" ")[1]
        if not token:
            logger.error("Token is empty after splitting.")
            raise HTTPException(status_code=401, detail="Token is empty.")

        payload = JWTManager.verify_token(token, "access")
        user_roles = payload.get("roles", [])

        if not isinstance(user_roles, list):
            logger.error(f"Invalid roles format in token: {user_roles}")
            raise HTTPException(status_code=500, detail="Internal server error: Invalid roles format in token.")

        from infrastructure.database.repository.rbac_repository import RBACRepository
        rbac_repo = RBACRepository()
        user_permissions = []

        for role in user_roles:
            try:
                permissions = await rbac_repo.get_role_permissions(role)
                if not isinstance(permissions, list):
                    logger.error(f"Invalid permissions format for role {role}: {permissions}")
                    raise HTTPException(status_code=500, detail=f"Invalid permissions format for role {role}.")
                user_permissions.extend(permissions)
            except Exception as e:
                logger.error(f"Error fetching permissions for role {role}: {str(e)}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Error fetching permissions for role {role}.")

        if not all(perm in user_permissions for perm in required_permissions):
            logger.warning(
                f"User lacks required permissions. Required: {required_permissions}, Found: {user_permissions}")
            raise HTTPException(status_code=403, detail="Unauthorized: Insufficient permissions.")

        logger.info(f"Permission check passed for permissions: {required_permissions}")
        return True

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error in permission middleware: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during permission validation.")