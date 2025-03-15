# app/middleware/rate_limit.py
import logging

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.errors import InternalServerError

logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)


def setup_rate_limit(app):
    """Set up rate limiting for the FastAPI application.

    Args:
        app: The FastAPI application instance.

    Raises:
        InternalServerError: If rate limiting setup fails due to configuration or runtime issues.
    """
    try:
        app.state.limiter = limiter
        logger.info("Rate limiting initialized successfully (applied via route decorators)")
    except AttributeError as ae:
        logger.error(f"AttributeError during rate limit setup: {str(ae)}", exc_info=True)
        raise InternalServerError(f"Failed to setup rate limiting: Invalid app instance - {str(ae)}")
    except ValueError as ve:
        logger.error(f"ValueError during rate limit setup: {str(ve)}", exc_info=True)
        raise InternalServerError(f"Failed to setup rate limiting: Configuration error - {str(ve)}")
    except Exception as e:
        logger.error(f"Unexpected error during rate limit setup: {str(e)}", exc_info=True)
        raise InternalServerError(f"Failed to setup rate limiting: {str(e)}")
