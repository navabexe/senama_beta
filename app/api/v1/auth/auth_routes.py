# app/api/v1/auth/auth_routes.py
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Body, Request
from app.security.jwt import JWTManager
from app.services.auth.auth_service import AuthService
from app.services.auth.otp_service import OTPService
from app.services.auth.token_service import TokenService
from app.domain.schemas.auth_schema import LoginRequest, OTPVerificationRequest, TokenResponse, OTPResponse
from app.middleware.rbac import role_based_access_control, get_jwt_manager
from user_agents import parse

logger = logging.getLogger(__name__)

# Router setup
router = APIRouter(prefix="/auth", tags=["Authentication"])

# Service instances
try:
    auth_service = AuthService()
    otp_service = OTPService()
    token_service = TokenService()
    logger.info("Authentication services initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize authentication services: {str(e)}", exc_info=True)
    raise Exception("Service initialization failed.")

@router.post("/login", response_model=OTPResponse)
async def login_user(request: LoginRequest):
    """
    Initiates login or registration by sending an OTP.
    If the user exists, it's a login OTP; if not, it's a registration OTP.
    """
    try:
        result = await auth_service.login(request)
        logger.info(f"OTP sent for phone: {request.phone_number}, action: {result['action']}")
        return OTPResponse(**result)
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during login for {request.phone_number}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during login.")

@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(request: OTPVerificationRequest, http_request: Request):
    """
    Verifies the OTP and either registers a new user or logs in an existing user.
    """
    try:
        result = await auth_service.verify_otp(request, http_request)
        logger.info(f"OTP verified successfully for phone: {request.phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during OTP verification: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during OTP verification.")

@router.post("/refresh-token", response_model=TokenResponse)
async def refresh_token(refresh_token: str = Body(..., embed=True)):
    try:
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Refresh token is required.")
        result = token_service.refresh_access_token(refresh_token)
        logger.info("Token refreshed successfully.")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during token refresh: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during token refresh.")

@router.post("/logout", response_model=dict)
async def logout_user(user_id: str = Body(..., embed=True), session_id: str = None):
    """
    Log out a user from a specific session or all sessions.
    """
    try:
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required.")
        result = await auth_service.logout(user_id, session_id)
        logger.info(f"User logged out: {user_id}, Session: {session_id or 'all'}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during logout.")

async def admin_role_check(request: Request, jwt_manager: JWTManager = Depends(get_jwt_manager)):
    await role_based_access_control(request, ["admin"], jwt_manager)
    return True

@router.post("/force-logout", response_model=dict, dependencies=[Depends(admin_role_check)])
async def force_logout_admin(user_id: str = Body(..., embed=True)):
    """
    Force logout a user by admin.
    Requires 'admin' role.
    """
    try:
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required.")
        result = await auth_service.force_logout(user_id)
        logger.info(f"Admin forced logout for user: {user_id}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during force logout: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during force logout.")

@router.post("/send-otp", response_model=OTPResponse)
async def send_otp(phone_number: str = Body(..., embed=True)):
    """
    Send an OTP to a user's phone number (for testing or additional flows).
    """
    try:
        if not phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required.")
        user = await auth_service.auth_repository.get_user_by_phone(phone_number)
        otp_type = "login" if user else "register"
        otp_code, otp_id = auth_service.otp_manager.generate_otp(phone_number, otp_type)
        await auth_service.sms_service.send_sms(phone_number, f"Your OTP code: {otp_code}")
        logger.info(f"OTP sent successfully to phone: {phone_number}, action: {otp_type}")
        return OTPResponse(message=f"OTP sent for {otp_type}.", action=otp_type)
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error sending OTP to {phone_number}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error sending OTP.")

async def user_role_check(request: Request, jwt_manager: JWTManager = Depends(get_jwt_manager)):
    await role_based_access_control(request, ["user", "vendor"], jwt_manager)
    return True

@router.get("/sessions", response_model=dict, dependencies=[Depends(user_role_check)])
async def get_active_sessions(user_id: str = Body(..., embed=True)):
    """
    Get active sessions for a user.
    Requires 'user' role.
    """
    try:
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required.")
        result = await auth_service.get_active_sessions(user_id)
        logger.info(f"Active sessions retrieved for user: {user_id}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error retrieving active sessions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error retrieving sessions.")

@router.post("/request-account-deletion", response_model=dict)
async def request_account_deletion(request: OTPVerificationRequest):
    """
    Request account deletion by verifying OTP.
    """
    try:
        result = await auth_service.request_account_deletion(request.phone_number, request.otp_code, request.otp_id)
        logger.info(f"Account deletion requested for phone: {request.phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during account deletion request for {request.phone_number}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during account deletion request.")

from app.security.hashing import Hashing

@router.post("/login-password", response_model=TokenResponse)
async def login_with_password(username: str = Body(...), password: str = Body(...), http_request: Request = None):
    """
    Log in a user with username and password.
    """
    try:
        user = await auth_service.auth_repository.get_user_by_username(username)
        if not user:
            logger.warning(f"No user found for username: {username}")
            raise HTTPException(status_code=404, detail="User not found.")

        if not Hashing().verify_password(password, user["password"]):
            logger.warning(f"Invalid password for username: {username}")
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        user_id = str(user["_id"])
        roles = [user.get("role", "user")]

        access_token = auth_service.jwt_manager.create_access_token(user_id, roles, user.get("phone_number", "unknown"))
        refresh_token = auth_service.jwt_manager.create_refresh_token(user_id)

        session_id = f"session-{datetime.now(timezone.utc).isoformat()}"
        user_agent_str = http_request.headers.get("User-Agent", "unknown") if http_request else "unknown"
        user_agent = parse(user_agent_str)
        device_info = {
            "device": user_agent.device.family,
            "browser": user_agent.browser.family,
            "os": user_agent.os.family,
            "ip": http_request.client.host if http_request else "127.0.0.1"
        }
        await auth_service.redis_service.store_session(user_id, session_id, device_info)

        logger.info(f"User logged in with username: {username}")
        return TokenResponse(access_token=access_token, refresh_token=refresh_token, message="Login successful.", action="login")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during password login for {username}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during login.")