from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from app.core.config import settings
from app.core.logging import logger
from app.core.request_limits import RequestBodyLimitMiddleware
from app.database.init_db import init_db
from app.api.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager: runs startup DB initialization and handles graceful shutdown.
    """
    logger.info(f"Starting {settings.APP_NAME} in '{settings.APP_ENV}' mode...")
    init_db()
    yield
    logger.info(f"Shutting down {settings.APP_NAME} gracefully...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Secure REST API for AI-Based Cybersecurity Threat Detection & Response System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Limit request bodies before JSON parsing. CORS is installed after this so
# cross-origin clients receive the same structured rejection response.
app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=65_536)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for HTTP Security Headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Exception Handler for HTTP Exceptions (401, 403, 404, etc.)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if (
        exc.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}
        and request.url.path in {
            f"{settings.API_PREFIX}/events",
            f"{settings.API_PREFIX}/detection/analyze",
        }
    ):
        logger.warning("Rejected unauthorized ingestion request for %s", request.url.path)
    headers = getattr(exc, "headers", None)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers
    )


# Exception Handler for Pydantic Validation Errors
@app.exception_handler(RequestValidationError)
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    safe_errors = [
        {"type": error["type"], "loc": error["loc"], "msg": "Invalid request value."}
        for error in exc.errors()
    ]
    logger.warning("Request validation failed for %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation failed for request parameters.",
            "errors": safe_errors
        }
    )


# Global Exception Handler for Unhandled Server Errors (500)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled request failure for %s %s (%s)",
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An unexpected internal server error occurred."
        }
    )


# Register Versioned API Routers
app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/")
def root():
    return {
        "message": f"Welcome to {settings.APP_NAME} API",
        "docs": "/docs",
        "health": f"{settings.API_PREFIX}/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
