import logging
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from app.api.v1.auth.auth_routes import router as auth_router
from infrastructure.database.client import DatabaseClient
from scripts.init_db import initialize_database
import uvicorn

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan management for startup and shutdown events.
    Initializes the database on startup.
    """
    try:
        DatabaseClient.get_client()
        logger.info("Database client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database client: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to initialize database client.")

    try:
        await initialize_database()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Database initialization failed.")

    yield
    logger.info("Application shutdown completed.")


# FastAPI application setup
try:
    app = FastAPI(
        title="Marketplace Authentication API",
        version="1.0",
        lifespan=lifespan
    )
    logger.info("FastAPI application initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize FastAPI application: {str(e)}", exc_info=True)
    raise Exception("Failed to start application.")


# Default route
@app.get("/")
def root():
    """
    Default endpoint to check if the API is running.
    """
    try:
        return {"message": "Marketplace API is running!"}
    except Exception as e:
        logger.error(f"Error in root endpoint: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error in root endpoint.")


# Include API routers
try:
    app.include_router(auth_router, prefix="/api/v1")
    logger.info("API routers included successfully.")
except Exception as e:
    logger.error(f"Failed to include API routers: {str(e)}", exc_info=True)
    raise HTTPException(status_code=500, detail="Failed to configure API routes.")

# Run the server
if __name__ == "__main__":
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000)
        logger.info("Server started successfully on 0.0.0.0:8000.")
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}", exc_info=True)
        raise Exception("Server startup failed.")