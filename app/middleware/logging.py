# app/middleware/logging.py
import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.errors import InternalServerError

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log incoming requests and outgoing responses."""

    async def dispatch(cls, request: Request, call_next) -> Response:
        """Log request and response details.

        Args:
            request (Request): The incoming HTTP request.
            call_next: The next middleware or endpoint to process the request.

        Returns:
            Response: The HTTP response after processing.

        Raises:
            InternalServerError: If an unexpected error occurs during request processing.
        """
        try:
            logger.info(
                f"Request: {request.method} {request.url.path} "
                f"from {request.client.host} "
                f"headers={dict(request.headers)}"
            )

            response = await call_next(request)

            logger.info(
                f"Response: {request.method} {request.url.path} "
                f"status={response.status_code}"
            )

            return response

        except ValueError as ve:
            logger.error(f"ValueError in request processing: {str(ve)}", exc_info=True)
            raise InternalServerError(f"Invalid request data: {str(ve)}")
        except RuntimeError as re:
            logger.error(f"RuntimeError in request processing: {str(re)}", exc_info=True)
            raise InternalServerError(f"Request processing failed: {str(re)}")
        except Exception as e:
            logger.error(f"Unexpected error in request processing: {str(e)}", exc_info=True)
            raise InternalServerError(f"Internal server error: {str(e)}")
