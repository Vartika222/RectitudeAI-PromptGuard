"""
Inference routes — all security logic delegated to the orchestrator.
This file should stay thin.
"""

from fastapi import APIRouter, Depends, HTTPException
from backend.models.requests import InferenceRequest
from backend.models.responses import InferenceResponse
from backend.gateway.security.auth.jwt_handler import get_current_user
from backend.gateway.security.auth.rate_limiter import rate_limit_dependency
from backend.gateway.llm.client import get_llm_client
from backend.layer5_orchestration.orchestrator import orchestrator
from backend.utils.exceptions import SecurityBlockError
from backend.utils.logging import get_logger
from backend.storage.audit_logs import AuditLogger
import json
import os
import uuid
import time
from datetime import datetime

router = APIRouter()
logger = get_logger(__name__)
_audit = AuditLogger()

# ── Escalation queue ──────────────────────────────────────────────────────────
# In-memory queue that survives the process lifetime. Written to disk so the
# RL reviewer and any webhook consumer can poll it. Cleared when items are
# reviewed via DELETE /v1/escalation/{request_id}.

_ESCALATION_QUEUE: list[dict] = []
_ESCALATION_FILE = "logs/escalation_queue.jsonl"


def _enqueue_escalation(result, req: InferenceRequest):
    entry = {
        "queued_at": datetime.utcnow().isoformat(),
        "request_id": result.request_id,
        "user_id": req.user_id,
        "session_id": req.conversation_id or req.user_id,
        "prompt": req.prompt[:200],
        "risk_score": result.risk_score,
        "asi_score": result.asi_score,
        "reason": result.reason,
        "signals": result.detector_signals,
        "reviewed": False,
    }
    _ESCALATION_QUEUE.append(entry)
    # Keep at most 200 in memory
    if len(_ESCALATION_QUEUE) > 200:
        _ESCALATION_QUEUE.pop(0)
    # Append to disk
    os.makedirs("logs", exist_ok=True)
    try:
        with open(_ESCALATION_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.error("Escalation queue write failed: %s", e)
    logger.warning(
        "ESCALATED request %s queued for review (risk=%.3f ASI=%.3f)",
        result.request_id, result.risk_score, result.asi_score,
    )


# ── Inference ─────────────────────────────────────────────────────────────────

@router.post("/v1/inference", response_model=InferenceResponse)
async def generate_response(
    req: InferenceRequest,
    user=Depends(get_current_user),
    _rl=Depends(rate_limit_dependency),
):
    # Phase 1: Pre-LLM security check
    pre_result = await orchestrator.process(req)

    if pre_result.decision == "block":
        raise SecurityBlockError(
            pre_result.reason,
            pre_result.risk_score,
            {
                "request_id": pre_result.request_id,
                "tier_reached": pre_result.tier_reached,
                "asi_score": pre_result.asi_score,
                "signals": pre_result.detector_signals,
            },
        )

    if pre_result.decision == "escalate":
        _enqueue_escalation(pre_result, req)
        # Escalated requests still proceed — the queue is for human review,
        # not a hard block. The ASI alert and elevated monitoring continue.

    # Phase 2: LLM call
    try:
        tool_names = [tc.name for tc in req.tool_calls] if req.tool_calls else []
        client = get_llm_client()
        llm_response = await client.generate(
            prompt=req.prompt,
            max_tokens=req.max_tokens,
            temperature=req.temperature,
        )
    except Exception as e:
        logger.error("LLM call failed: %s", e)
        raise HTTPException(status_code=500, detail="LLM inference failed")

    # Phase 3: Post-LLM output mediation + ASI update
    post_result = await orchestrator.process(
        req,
        llm_response=llm_response.response,
        tool_calls=tool_names or None,
    )

    if not post_result.output_safe:
        logger.warning(
            "Output mediation blocked leakage for request %s: %s",
            post_result.request_id,
            post_result.output_findings,
        )
        return InferenceResponse(
            response="[Response redacted by security mediator — potential data leakage detected]",
            tool_calls=[],
            metadata={
                "request_id": post_result.request_id,
                "redacted": True,
                "findings_count": len(post_result.output_findings),
                "latency_ms": post_result.latency_ms,
                "asi_score": post_result.asi_score,
            },
            request_id=post_result.request_id,
            timestamp=datetime.utcnow(),
        )

    return InferenceResponse(
        response=llm_response.response,
        tool_calls=[],
        metadata={
            "request_id": post_result.request_id,
            "latency_ms": post_result.latency_ms,
            "tier_reached": post_result.tier_reached,
            "risk_score": post_result.risk_score,
            "asi_score": post_result.asi_score,
            "asi_alert": post_result.asi_alert,
            "escalated": pre_result.decision == "escalate",
            "capability_token_issued": bool(post_result.capability_token),
        },
        request_id=post_result.request_id,
        timestamp=datetime.utcnow(),
    )


# ── Escalation queue endpoints ────────────────────────────────────────────────

@router.get("/v1/escalation")
async def get_escalation_queue(
    user=Depends(get_current_user),
    reviewed: bool = False,
):
    """Return pending escalated requests. reviewed=true includes already-reviewed items."""
    items = _ESCALATION_QUEUE if reviewed else [
        e for e in _ESCALATION_QUEUE if not e.get("reviewed")
    ]
    return {"count": len(items), "items": items}


@router.post("/v1/escalation/{request_id}/review")
async def review_escalation(
    request_id: str,
    action: str,   # "approve" | "block"
    user=Depends(get_current_user),
):
    """
    Mark an escalated request as reviewed.
    action=approve → logged as accepted, session monitoring continues.
    action=block   → logged as threat confirmed; future requests from that
                     session will have force_ml=True permanently via ASI alert.
    """
    for entry in _ESCALATION_QUEUE:
        if entry["request_id"] == request_id:
            entry["reviewed"] = True
            entry["review_action"] = action
            entry["reviewed_by"] = getattr(user, "username", str(user))
            entry["reviewed_at"] = datetime.utcnow().isoformat()

            if action == "block":
                # Drive the session's ASI suspicion above alert threshold
                from backend.layer3_behavior_monitor.asi_calculator import (
                    ASICalculator, _set_suspicion, SUSPICION_ALERT
                )
                sid = entry["session_id"]
                _set_suspicion(sid, SUSPICION_ALERT + 1.0)
                logger.warning(
                    "Escalation %s confirmed as threat by %s — session %s flagged",
                    request_id, entry["reviewed_by"], sid,
                )
                _audit.log_event({
                    "request_id": request_id,
                    "user_id": entry["user_id"],
                    "session_id": sid,
                    "decision": "block",
                    "risk_score": entry["risk_score"],
                    "reason": f"Manually confirmed threat by {entry['reviewed_by']}",
                    "tier_reached": 0,
                })
            return {"status": "reviewed", "action": action, "request_id": request_id}

    raise HTTPException(status_code=404, detail=f"Request {request_id} not in escalation queue")


# ── Session / audit endpoints ─────────────────────────────────────────────────

@router.get("/v1/session/{session_id}/asi")
async def get_session_asi(
    session_id: str,
    user=Depends(get_current_user),
):
    """Return current ASI score for a session. Used by the dashboard."""
    from backend.layer3_behavior_monitor.asi_calculator import ASICalculator
    calc = ASICalculator()
    risk = calc.get_risk_score(session_id)
    return {
        "session_id": session_id,
        "asi_score": round(1.0 - risk, 4),
        "risk_score": risk,
        "alert": risk >= 0.45,
    }


@router.post("/v1/session/{session_id}/reset")
async def reset_session(
    session_id: str,
    user=Depends(get_current_user),
):
    """Admin: reset a session's ASI history."""
    from backend.layer3_behavior_monitor.asi_calculator import ASICalculator
    ASICalculator().reset_session(session_id)
    return {"status": "reset", "session_id": session_id}


@router.get("/v1/audit/logs")
async def get_audit_logs(
    limit: int = 50,
    severity: str = None,
    user_id: str = None,
    user=Depends(get_current_user),
):
    """Return recent audit log entries."""
    return {
        "logs": _audit.get_logs(limit=limit, severity=severity, user_id=user_id),
        "stats": _audit.get_stats(),
    }