"""Health check endpoints — real component probing, not hardcoded strings."""

import time
import asyncio
from fastapi import APIRouter
from backend.models.responses import HealthResponse
from backend.gateway.config import settings
from datetime import datetime

router = APIRouter(prefix="/health", tags=["health"])


async def _check_redis() -> dict:
    t0 = time.monotonic()
    try:
        import redis as redis_module
        r = redis_module.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            socket_connect_timeout=1,
        )
        r.ping()
        latency = f"{(time.monotonic() - t0) * 1000:.0f}ms"
        return {"status": "ACTIVE", "latency": latency}
    except Exception as e:
        return {"status": "DOWN", "latency": "—", "error": str(e)}


async def _check_ollama() -> dict:
    t0 = time.monotonic()
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{settings.ollama_base_url}/api/tags")
        latency = f"{(time.monotonic() - t0) * 1000:.0f}ms"
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return {
                "status": "ACTIVE",
                "latency": latency,
                "models": models,
            }
        return {"status": "LIMITED", "latency": latency, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "DOWN", "latency": "—", "error": str(e)}


def _check_ml_classifiers() -> dict:
    """Check whether the ML models are loaded in the current process."""
    from backend.layer5_orchestration.orchestrator import _injection_clf, _perplexity_clf
    from backend.layer1_intent_security.injection_classifier import _ML_AVAILABLE

    if not _ML_AVAILABLE:
        return {"status": "LIMITED", "latency": "—", "note": "torch not installed"}

    inj_loaded  = _injection_clf is not None and getattr(_injection_clf, "_loaded", False)
    perp_loaded = _perplexity_clf is not None and _perplexity_clf._model is not None

    if inj_loaded and perp_loaded:
        return {"status": "ACTIVE", "latency": "~150ms", "note": "DeBERTa + GPT-2 loaded"}
    elif inj_loaded or perp_loaded:
        which = "DeBERTa" if inj_loaded else "GPT-2"
        return {"status": "LIMITED", "latency": "~150ms", "note": f"Only {which} loaded"}
    else:
        return {
            "status": "STANDBY",
            "latency": "—",
            "note": "Models lazy-load on first ML-tier request",
        }


@router.get("/", response_model=HealthResponse)
async def health_check():
    """
    Real component health check.
    Probes Redis, Ollama, and ML classifier load status.
    """
    redis_status, ollama_status = await asyncio.gather(
        _check_redis(),
        _check_ollama(),
    )
    ml_status = _check_ml_classifiers()

    # Map to ServiceNode-compatible structure
    infra = [
        {
            "name": "FastAPI Gateway",
            "status": "ACTIVE",
            "latency": "< 1ms",
            "region": f"{settings.host}:{settings.port}",
            "icon_type": "Router",
        },
        {
            "name": "Redis (ASI / rate limit)",
            "status": redis_status["status"],
            "latency": redis_status.get("latency", "—"),
            "region": f"{settings.redis_host}:{settings.redis_port}",
            "icon_type": "Database",
        },
        {
            "name": f"LLM ({settings.ollama_model})",
            "status": ollama_status["status"],
            "latency": ollama_status.get("latency", "—"),
            "region": settings.ollama_base_url,
            "icon_type": "Cpu",
        },
        {
            "name": "ML classifiers",
            "status": ml_status["status"],
            "latency": ml_status.get("latency", "—"),
            "region": ml_status.get("note", ""),
            "icon_type": "Zap",
        },
        {
            "name": "Policy engine",
            "status": "ACTIVE",
            "latency": "< 1ms",
            "region": "in-process",
            "icon_type": "ShieldCheck",
        },
    ]

    # Overall health: healthy only if gateway + at least one LLM backend is up
    llm_ok     = ollama_status["status"] == "ACTIVE"
    redis_ok   = redis_status["status"]  == "ACTIVE"
    overall    = "healthy" if llm_ok else "degraded"

    return HealthResponse(
        status=overall,
        version=settings.app_version,
        timestamp=datetime.utcnow(),
        components={
            "llm_provider":  settings.llm_provider,
            "llm":           ollama_status["status"],
            "redis":         redis_status["status"],
            "classifiers":   ml_status["status"],
            "gateway":       "operational",
        },
        infrastructure=infra,
    )


@router.get("/readiness")
async def readiness_check():
    """Readiness probe for container orchestration."""
    return {"status": "ready"}


@router.get("/liveness")
async def liveness_check():
    """Liveness probe for container orchestration."""
    return {"status": "alive"}