"""
SENTINEL-X — FastAPI Application Entry Point
==============================================
This is the main application module. It:
  - Creates the FastAPI app with metadata
  - Registers all routers
  - Configures middleware (CORS, rate limiting, request size)
  - Handles startup and shutdown lifecycle events
  - Configures structured logging

Run with:
    cd backend/
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

import logging
import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from app.config import get_settings

# ── Structured logging setup ──────────────────────────────────────────────────

def _configure_logging(level: str) -> None:
    """Configure structlog for JSON-formatted structured logging."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
    )


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.

    startup:
      - Configure logging
      - Create database tables
      - Initialize detector singletons (warm up TF-IDF model)

    shutdown:
      - Close database connections
    """
    settings = get_settings()
    _configure_logging(settings.log_level)
    log = structlog.get_logger("sentinel_x.startup")

    log.info("SENTINEL-X starting up", version=settings.app_version)

    # Create all database tables
    try:
        from app.db.database import create_all_tables
        await create_all_tables()
        log.info("Database tables initialized")
    except Exception as exc:
        log.error("Database initialization failed", error=str(exc))

    # Warm up detector singletons (loads TF-IDF model)
    try:
        from app.detectors.normalizer import get_normalizer
        from app.detectors.prompt_injection import get_injection_detector
        get_normalizer()
        det = get_injection_detector()
        # Trigger TF-IDF initialization
        det._layer2._initialize()
        if det._layer2.available:
            log.info("Prompt injection detector (Layer 2 TF-IDF) ready")
        else:
            log.warning(
                "Prompt injection Layer 2 unavailable",
                error=det._layer2._error,
                fallback="Layer 1 rule-based detection still active",
            )
    except Exception as exc:
        log.error("Detector initialization error", error=str(exc))

    log.info(
        "SENTINEL-X ready",
        host=settings.host,
        port=settings.port,
        llm_provider=settings.default_llm_provider,
    )

    yield  # Application runs here

    # Shutdown
    log.info("SENTINEL-X shutting down")
    try:
        from app.db.database import close_engine
        await close_engine()
    except Exception:
        pass
    log.info("Shutdown complete")


# ── Rate limiter ──────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="SENTINEL-X",
        description=(
            "Adaptive, Context-Aware Security Middleware / AI Firewall "
            "for Real-Time LLM Applications.\n\n"
            "**All API keys are optional. The system works fully with the Mock LLM.**"
        ),
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── Rate limiting ──────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── CORS ───────────────────────────────────────────────────────────────
    # In development: allow all origins (React dev server on different port)
    # In production: restrict to your actual frontend domain
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else ["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # ── Request logging middleware ─────────────────────────────────────────
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        # NOTE: We do NOT log request body here to avoid logging user content
        log = structlog.get_logger("sentinel_x.http")
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round(duration_ms, 2),
        )
        return response

    # ── Global exception handler ───────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        log = structlog.get_logger("sentinel_x.error")
        log.error(
            "unhandled_exception",
            path=request.url.path,
            error_type=type(exc).__name__,
            # We intentionally do NOT log the full traceback here to avoid
            # potentially sensitive data leaking through error messages.
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error. Request blocked as fail-safe measure.",
                "error_type": type(exc).__name__,
            },
        )

    # ── Routers ────────────────────────────────────────────────────────────
    from app.api.health import router as health_router
    from app.api.analyze import router as analyze_router
    from app.api.chat import router as chat_router
    from app.api.audit import router as audit_router
    from app.api.document import router as document_router

    app.include_router(health_router)                                    # GET /health
    app.include_router(analyze_router, prefix="/api/v1")                 # POST /api/v1/analyze/input
    app.include_router(chat_router, prefix="/api/v1")                    # POST /api/v1/chat
    app.include_router(audit_router, prefix="/api/v1")                   # GET /api/v1/audit/...
    app.include_router(document_router, prefix="/api/v1")

    return app


# ── Application instance (imported by uvicorn) ────────────────────────────────
app = create_app()


# ── Development entrypoint ────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
