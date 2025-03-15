from fastapi import HTTPException
from httpcore import Request

from app.security.jwt import JWTManager
from infrastructure.database.client import DatabaseClient
from typing import List


class RBACRepository:
    def __init__(self):
        self.db = DatabaseClient.get_database()
        self.permissions = self.db["permissions"]

    async def get_role_permissions(self, role: str) -> List[str]:
        result = await self.permissions.find_one({"role": role})
        return result.get("permissions", []) if result else []


async def permission_based_access_control(request: Request, required_permissions: List[str]):
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication token not provided.")

    token = token.split(" ")[1]
    payload = JWTManager.verify_token(token, "access")
    user_roles = payload.get("roles", [])
    rbac_repo = RBACRepository()
    user_permissions = []

    for role in user_roles:
        user_permissions.extend(await rbac_repo.get_role_permissions(role))

    if not all(perm in user_permissions for perm in required_permissions):
        raise HTTPException(status_code=403, detail="Unauthorized: Insufficient permissions.")