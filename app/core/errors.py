# core/errors.py
import logging
from typing import Optional

from fastapi import HTTPException

logger = logging.getLogger(__name__)

class BaseError(HTTPException):
    """Base class for custom HTTP exceptions.

    Args:
        status_code (int): HTTP status code for the error.
        detail (str): Detailed message describing the error.
    """
    def __init__(cls, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)
        logger.error(f"Error occurred: {detail} (Status: {status_code})")

class NotFoundError(BaseError):
    """Exception raised for resources that cannot be found.

    Args:
        detail (str, optional): Specific detail about what was not found. Defaults to "Item not found".
    """

    def __init__(cls, detail: Optional[str] = "Item not found"):
        super().__init__(status_code=404, detail=detail)

class ValidationError(BaseError):
    """Exception raised for invalid input data.

    Args:
        detail (str, optional): Specific detail about the validation failure. Defaults to "Invalid input".
    """

    def __init__(cls, detail: Optional[str] = "Invalid input"):
        super().__init__(status_code=400, detail=detail)

class UnauthorizedError(BaseError):
    """Exception raised for unauthorized access attempts.

    Args:
        detail (str, optional): Specific detail about the authorization failure. Defaults to "Unauthorized".
    """

    def __init__(cls, detail: Optional[str] = "Unauthorized"):
        super().__init__(status_code=401, detail=detail)

class InternalServerError(BaseError):
    """Exception raised for unexpected server-side errors.

    Args:
        detail (str, optional): Specific detail about the server error. Defaults to "Internal server error".
    """

    def __init__(cls, detail: Optional[str] = "Internal server error"):
        super().__init__(status_code=500, detail=detail)