# infrastructure/external/logging/setup.py
import logging
import logging.config

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.errors import InternalServerError


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log incoming requests and outgoing responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        """Log request and response details."""
        logger = logging.getLogger("senama_app")
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
            logger.error(f"ValueError: {str(ve)}", exc_info=True)
            raise InternalServerError(f"Invalid request data: {str(ve)}")
        except RuntimeError as re:
            logger.error(f"RuntimeError: {str(re)}", exc_info=True)
            raise InternalServerError(f"Request processing failed: {str(re)}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            raise InternalServerError(f"Internal server error: {str(e)}")

def setup_logging(app: FastAPI) -> None:
    """Set up logging configuration for the application."""
    global logger
    try:
        LOGGING_CONFIG = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "app.log",
                    "level": "DEBUG",
                    "formatter": "default",
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "DEBUG",
                    "formatter": "default",
                },
            },
            "loggers": {
                "senama_app": {
                    "level": "DEBUG",
                    "handlers": ["file", "console"],
                    "propagate": False,
                },
            },
            "root": {
                "level": "DEBUG",
                "handlers": ["console"],
            },
        }

        logging.config.dictConfig(LOGGING_CONFIG)
        app.add_middleware(LoggingMiddleware)

        logger = logging.getLogger("senama_app")
        logger.info("Logging setup completed")

    except ValueError as ve:
        logger.error(f"Invalid config: {str(ve)}", exc_info=True)
        raise InternalServerError(f"Invalid logging configuration: {str(ve)}")
    except FileNotFoundError as fnf:
        logger.error(f"File path error: {str(fnf)}", exc_info=True)
        raise InternalServerError(f"Log file path error: {str(fnf)}")
    except PermissionError as pe:
        logger.error(f"Permission denied: {str(pe)}", exc_info=True)
        raise InternalServerError(f"Permission denied: {str(pe)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        raise InternalServerError(f"Unexpected error: {str(e)}")