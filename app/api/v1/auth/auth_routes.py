import logging
from fastapi import APIRouter, HTTPException, Depends, Body, Request

from app.security.jwt import JWTManager
from app.services.auth.auth_service import AuthService
from app.services.auth.otp_service import OTPService
from app.services.auth.token_service import TokenService
from app.domain.schemas.auth_schema import LoginRequest, OTPVerificationRequest, TokenResponse
from app.middleware.rbac import role_based_access_control, get_jwt_manager

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


@router.post("/register", response_model=dict)
async def register_user(request: LoginRequest):
    """
    Register a new user by sending an OTP.
    """
    try:
        result = await auth_service.register_user(request)
        logger.info(f"User registration initiated for phone: {request.phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during user registration: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during registration.")


@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(request: OTPVerificationRequest, http_request: Request):
    try:
        result = await auth_service.verify_otp(request, http_request)
        logger.info(f"OTP verified successfully for phone: {request.phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during OTP verification: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during OTP verification.")


@router.post("/login", response_model=dict)
async def login_user(request: LoginRequest):
    """
    Log in a user and send an OTP.
    """
    try:
        result = await auth_service.login(request)
        logger.info(f"Login OTP sent for phone: {request.phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during user login: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during login.")


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


@router.post("/force-logout", response_model=dict,
             dependencies=[Depends(lambda: role_based_access_control(["admin"]))])
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


@router.post("/send-otp", response_model=dict)
async def send_otp(phone_number: str = Body(..., embed=True)):
    """
    Send an OTP to a user's phone number.
    """
    try:
        if not phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required.")
        result = await otp_service.send_otp(phone_number)
        logger.info(f"OTP sent successfully to phone: {phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error sending OTP to {phone_number}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error sending OTP.")


async def user_role_check(request: Request, jwt_manager: JWTManager = Depends(get_jwt_manager)):
    await role_based_access_control(request, ["user"], jwt_manager)
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
        result = await auth_service.request_account_deletion(request.phone_number, request.otp_code)
        logger.info(f"Account deletion requested for phone: {request.phone_number}")
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during account deletion request for {request.phone_number}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during account deletion request.")
