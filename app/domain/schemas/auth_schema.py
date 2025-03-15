# app/domain/schemas/auth_schema.py
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class LoginRequest(BaseModel):
    """
    Data model for user login request.
    """
    phone_number: str = Field(..., example="+989123456789", description="User's phone number in international format.")

    class Config:
        json_schema_extra = {
            "example": {"phone_number": "+989123456789"}
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in LoginRequest: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid LoginRequest data: {str(e)}")

class OTPVerificationRequest(BaseModel):
    """
    Data model for OTP verification request.
    """
    phone_number: str = Field(..., example="+989123456789", description="User's phone number in international format.")
    otp_code: str = Field(..., min_length=6, max_length=6, example="123456", description="6-digit OTP code.")

    class Config:
        json_schema_extra = {
            "example": {"phone_number": "+989123456789", "otp_code": "123456"}
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in OTPVerificationRequest: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid OTPVerificationRequest data: {str(e)}")

class TokenResponse(BaseModel):
    """
    Data model for authentication token response.
    """
    access_token: str = Field(..., description="JWT access token.")
    refresh_token: str = Field(..., description="JWT refresh token.")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in TokenResponse: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid TokenResponse data: {str(e)}")

class RefreshTokenRequest(BaseModel):
    """
    Data model for refresh token request.
    """
    refresh_token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", description="JWT refresh token.")

    class Config:
        json_schema_extra = {
            "example": {"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in RefreshTokenRequest: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid RefreshTokenRequest data: {str(e)}")

class LogoutRequest(BaseModel):
    """
    Data model for logout request.
    """
    user_id: str = Field(..., example="60ae1aa5017fda7b6a04256b", description="Unique user identifier.")
    session_id: Optional[str] = Field(None, example="session-12345", description="Optional session ID to logout from a specific session.")

    class Config:
        json_schema_extra = {
            "example": {"user_id": "60ae1aa5017fda7b6a04256b", "session_id": "session-12345"}
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in LogoutRequest: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid LogoutRequest data: {str(e)}")

class SessionResponse(BaseModel):
    """
    Data model for displaying active user sessions.
    """
    active_sessions: List[dict] = Field(..., description="List of active sessions with details.")

    class Config:
        json_schema_extra = {
            "example": {
                "active_sessions": [
                    {"session_id": "session-12345", "device": "iPhone", "last_active": "2025-03-15T10:00:00Z"}
                ]
            }
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in SessionResponse: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid SessionResponse data: {str(e)}")

class ForceLogoutRequest(BaseModel):
    """
    Data model for admin force logout request.
    """
    user_id: str = Field(..., example="60ae1aa5017fda7b6a04256b", description="Unique user identifier.")

    class Config:
        json_schema_extra = {
            "example": {"user_id": "60ae1aa5017fda7b6a04256b"}
        }

    @classmethod
    def validate(cls, value):
        try:
            return super().validate(value)
        except Exception as e:
            logger.error(f"Validation error in ForceLogoutRequest: {str(e)}", exc_info=True)
            raise ValueError(f"Invalid ForceLogoutRequest data: {str(e)}")