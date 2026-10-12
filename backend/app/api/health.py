"""
SENTINEL-X — Health Check Endpoint
=====================================
GET /health

Returns the current operational status of SENTINEL-X and its components.
Used by monitoring tools, load balancers, and the frontend dashboard
to detect degraded service states.

Note: This endpoint does NOT require authentication in Phase 1.
In a production deployment, health details should be protected.
"""

import time
from datetime import datetime, timezone

from fastapi import APIRouter

from app.schemas.response import HealthResponse

router = APIRouter()

# Module-level startup time for uptime calculation
_startup_time = time.monotonic()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Returns the operational status of SENTINEL-X and its components.",
    tags=["System"],
)
async def health_check() -> HealthResponse:
    """
    Check the health of all SENTINEL-X components.

    Returns:
        HealthResponse with status of each detector and the database.
        Status is 'ok' if all critical components are available,
        'degraded' if some optional components are unavailable,
        'error' if critical components have failed.
    """
    from app.config import get_settings
    settings = get_settings()

    detector_status: dict[str, str] = {}
    all_ok = True

    # Check Prompt Injection Detector (Layer 1 always available — pure stdlib)
    try:
        from app.detectors.prompt_injection import get_injection_detector
        detector = get_injection_detector()
        # Quick sanity check
        result = detector.analyze("hello world")
        detector_status["prompt_injection_layer1"] = "ok"

        # Check Layer 2 (TF-IDF — requires scikit-learn)
        if detector._layer2.available:
            detector_status["prompt_injection_layer2_tfidf"] = "ok"
        else:
            detector_status["prompt_injection_layer2_tfidf"] = "unavailable"
            # Layer 2 is degraded but not critical (Layer 1 still works)

    except Exception as exc:
        detector_status["prompt_injection"] = f"error: {type(exc).__name__}"
        all_ok = False

    # Check Normalizer
    try:
        from app.detectors.normalizer import get_normalizer
        norm = get_normalizer()
        norm.normalize("test")
        detector_status["normalizer"] = "ok"
    except Exception as exc:
        detector_status["normalizer"] = f"error: {type(exc).__name__}"
        all_ok = False

    # Check Database
    db_status = "ok"
    try:
        from app.db.database import get_db_session
        from sqlalchemy import text
        async with get_db_session() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {type(exc).__name__}"
        all_ok = False

    # Check PII Detector
    try:
        from app.detectors import get_pii_detector
        det = get_pii_detector()
        det.analyze("test@example.com")
        detector_status["pii_detector"] = "ok"
    except Exception as exc:
        detector_status["pii_detector"] = f"error: {type(exc).__name__}"
        all_ok = False

    # Check Secret Detector
    try:
        from app.detectors import get_secret_detector
        det = get_secret_detector()
        det.analyze("test string")
        detector_status["secret_detector"] = "ok"
    except Exception as exc:
        detector_status["secret_detector"] = f"error: {type(exc).__name__}"
        all_ok = False

    # Check Toxicity Detector
    try:
        from app.detectors import get_toxicity_detector
        det = get_toxicity_detector()
        det.analyze("hello world")
        detector_status["toxicity_detector"] = "ok"
    except Exception as exc:
        detector_status["toxicity_detector"] = f"error: {type(exc).__name__}"
        all_ok = False

    # Check Intent Analyzer
    try:
        from app.detectors import get_intent_analyzer
        det = get_intent_analyzer()
        det.analyze("help me")
        detector_status["intent_analyzer"] = "ok"
    except Exception as exc:
        detector_status["intent_analyzer"] = f"error: {type(exc).__name__}"
        all_ok = False

    status = "ok" if all_ok else "degraded"
    # Check if any critical component failed
    if any("error" in v for v in detector_status.values() if "layer1" not in v.lower()):
        status = "error"

    uptime = time.monotonic() - _startup_time

    return HealthResponse(
        status=status,
        version=settings.app_version,
        detectors=detector_status,
        database=db_status,
        uptime_seconds=round(uptime, 2),
    )
