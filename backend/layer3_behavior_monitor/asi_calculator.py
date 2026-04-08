"""
Agent Stability Index (ASI) — sliding-window behavioural drift monitor.

Runs as a background scorer per session. Does NOT block synchronously —
it returns a score that the orchestrator uses to adjust routing on the
*next* request. That's intentional: it detects slow multi-turn attacks.

Improvements over baseline:
  - Sentence-embedding similarity (all-MiniLM-L6-v2) with BoW fallback
  - Dual windows (short=5, long=20) with short/long divergence signal
  - Exponential decay weighting on historical interactions
  - Multiplicative penalty when multiple signals fire together
  - Per-user baseline (stored in Redis) with deviation scoring
  - Directional LDFR: shifts *toward* capability probing penalised harder
  - Temporal features: inter-request timing, burst detection
  - Soft cumulative suspicion score with decay (replaces binary counter)
  - High-ASI sessions expose modulation hints to the orchestrator

Metrics:
  C    — consistency (semantic similarity, exponentially weighted)
  T    — tool usage stability
  B    — boundary stability (token variance + block persistence)
  LDFR — directional latent diagnosis flip rate
  DIV  — short-window vs long-window divergence
  BURST — inter-request timing anomaly

ASI = 0.30*C + 0.25*T + 0.20*B + 0.15*(1-LDFR) + 0.05*(1-DIV) + 0.05*(1-BURST)

Alert fires when cumulative soft suspicion >= SUSPICION_ALERT.
"""

from __future__ import annotations
import math
import json
import time
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import redis as _redis_module
    from backend.gateway.config import settings as _settings
    _r = _redis_module.Redis(
        host=_settings.redis_host,
        port=_settings.redis_port,
        db=_settings.redis_db,
        decode_responses=True,
        socket_connect_timeout=2,
    )
    _r.ping()
    _REDIS_OK = True
except Exception:
    _r = None
    _REDIS_OK = False

_LOCAL_STORE: dict = {}

# Optional sentence-transformers for semantic similarity
_EMBED_MODEL = None
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    _EMBED_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    _NP_OK = True
except Exception:
    try:
        import numpy as np  # noqa: F401
        _NP_OK = True
    except ImportError:
        _NP_OK = False

SHORT_WINDOW       = 5     # recent turns for divergence signal
LONG_WINDOW        = 20    # full history cap
ALERT_THRESHOLD    = 0.55  # ASI below this adds to suspicion
SUSPICION_CEILING  = 4.0
SUSPICION_ALERT    = 2.0   # fires the alert
SUSPICION_DECAY    = 0.30  # decrement per clean window
BASELINE_MIN_OBS   = 8     # observations before baseline is locked
DECAY_LAMBDA       = 0.35  # exponential weight bias toward recency

# Capability-probing vocabulary — topic shifts toward these score harder
_CAP_PROBE_TERMS = {
    "tools", "access", "database", "files", "api", "keys", "admin",
    "system", "password", "credentials", "data", "export", "list users",
    "root", "override", "bypass", "ignore", "disregard", "forget",
    "instructions", "rules", "restrictions", "permissions",
}

_BENIGN_TERMS = {
    "weather", "recipe", "history", "sport", "movie", "book", "travel",
    "cooking", "music", "language", "math", "science", "poetry",
}


# ── Storage helpers ──────────────────────────────────────────────────────────

def _kv_get(key: str, default=None):
    if _REDIS_OK and _r:
        raw = _r.get(key)
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return _LOCAL_STORE.get(key, default)


def _kv_set(key: str, value, ttl: int = 7200):
    if _REDIS_OK and _r:
        _r.setex(key, ttl, json.dumps(value))
    else:
        _LOCAL_STORE[key] = value


def _get_session(session_id: str) -> list:
    return _kv_get(f"asi:session:{session_id}", [])


def _save_session(session_id: str, data: list):
    _kv_set(f"asi:session:{session_id}", data)


def _get_suspicion(session_id: str) -> float:
    return float(_kv_get(f"asi:suspicion:{session_id}", 0.0))


def _set_suspicion(session_id: str, val: float):
    _kv_set(f"asi:suspicion:{session_id}", round(min(val, SUSPICION_CEILING), 4))


def _get_baseline(session_id: str) -> Optional[dict]:
    return _kv_get(f"asi:baseline:{session_id}", None)


def _set_baseline(session_id: str, baseline: dict):
    _kv_set(f"asi:baseline:{session_id}", baseline, ttl=86400)


# ── Similarity ────────────────────────────────────────────────────────────────

def _embed_sim(a: str, b: str) -> float:
    """Semantic similarity via sentence embeddings; falls back to BoW."""
    if _EMBED_MODEL is not None:
        try:
            import numpy as np
            vecs = _EMBED_MODEL.encode([a, b], normalize_embeddings=True)
            return float(np.dot(vecs[0], vecs[1]))
        except Exception:
            pass
    return _cosine_sim_bow(a, b)


def _cosine_sim_bow(a: str, b: str) -> float:
    def vec(text: str) -> dict:
        v: dict = {}
        for w in text.lower().split():
            v[w] = v.get(w, 0) + 1
        return v
    va, vb = vec(a), vec(b)
    common = set(va) & set(vb)
    if not common:
        return 0.0
    dot = sum(va[w] * vb[w] for w in common)
    mag_a = math.sqrt(sum(x**2 for x in va.values()))
    mag_b = math.sqrt(sum(x**2 for x in vb.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _decay_weights(n: int) -> List[float]:
    """Exponential decay weights; most recent index = highest weight."""
    raw = [math.exp(DECAY_LAMBDA * i) for i in range(n)]
    total = sum(raw)
    return [w / total for w in raw]


def _coefficient_of_variation(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance) / mean


def _topic_direction(prompt: str) -> str:
    lower = prompt.lower()
    probe  = sum(1 for t in _CAP_PROBE_TERMS if t in lower)
    benign = sum(1 for t in _BENIGN_TERMS    if t in lower)
    if probe > benign:
        return "probing"
    if benign > probe:
        return "benign"
    return "neutral"


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class ASISnapshot:
    session_id: str
    asi: float
    c_consistency: float
    t_tool: float
    b_boundaries: float
    ldfr: float
    divergence: float
    burst: float
    suspicion: float
    alert: bool
    window_count: int
    ml_threshold_tighten: float    # delta for orchestrator to use
    require_token_reverify: bool
    timestamp: float = field(default_factory=time.time)


# ── Calculator ────────────────────────────────────────────────────────────────

class ASICalculator:

    def compute(
        self,
        prompt: str,
        session_id: str,
        tool_invoked: Optional[str] = None,
        response_token_count: int = 0,
        blocked: bool = False,
    ) -> ASISnapshot:
        history = _get_session(session_id)

        history.append({
            "prompt": prompt,
            "tool": tool_invoked,
            "tokens": response_token_count,
            "blocked": blocked,
            "ts": time.time(),
        })
        if len(history) > LONG_WINDOW:
            history = history[-LONG_WINDOW:]
        _save_session(session_id, history)

        if len(history) < 3:
            return ASISnapshot(
                session_id=session_id, asi=1.0,
                c_consistency=1.0, t_tool=1.0,
                b_boundaries=1.0, ldfr=0.0,
                divergence=0.0, burst=0.0,
                suspicion=0.0,
                alert=False, window_count=len(history),
                ml_threshold_tighten=0.0,
                require_token_reverify=False,
            )

        short_hist = history[-SHORT_WINDOW:]
        long_hist  = history

        prompts_long  = [e["prompt"] for e in long_hist]
        prompts_short = [e["prompt"] for e in short_hist]
        tools         = [e["tool"]   for e in long_hist]
        tokens        = [e["tokens"] for e in long_hist]
        timestamps    = [e["ts"]     for e in long_hist]

        # ── C: Consistency (exponentially weighted semantic similarity) ───
        sims_long = [
            max(_embed_sim(prompts_long[i], prompts_long[i - 1]), 0.30)
            for i in range(1, len(prompts_long))
        ]
        if sims_long:
            weights = _decay_weights(len(sims_long))
            c_consistency = sum(w * s for w, s in zip(weights, sims_long))
        else:
            c_consistency = 1.0

        # ── T: Tool usage stability ───────────────────────────────────────
        unique_tools = set(t for t in tools if t)
        if not unique_tools:
            t_tool = 1.0
        else:
            first_half_tools = set(t for t in tools[:len(tools)//2] if t)
            new_tools_late = unique_tools - first_half_tools
            t_tool = max(0.0, 1.0 - len(new_tools_late) * 0.25)

        # ── B: Boundary stability (weighted token CV) ─────────────────────
        token_vals = [float(t) for t in tokens if t > 0]
        if token_vals:
            tw = _decay_weights(len(token_vals))
            wmean = sum(w * v for w, v in zip(tw, token_vals))
            if wmean > 0:
                wvar = sum(tw[i] * (token_vals[i] - wmean)**2
                           for i in range(len(token_vals)))
                wcv = math.sqrt(wvar) / wmean
            else:
                wcv = 0.0
            b_boundaries = max(0.0, 1.0 - min(wcv, 1.0))
        else:
            b_boundaries = 1.0

        blocked_count = sum(1 for e in long_hist if e.get("blocked"))
        if blocked_count >= 2:
            b_boundaries *= max(0.0, 1.0 - (blocked_count - 1) * 0.15)

        # ── LDFR: Directional flip rate ───────────────────────────────────
        flip_score = 0.0
        n_pairs = max(len(sims_long), 1)
        for i, s in enumerate(sims_long):
            if s < 0.15:
                curr_dir = _topic_direction(prompts_long[i + 1])
                prev_dir = _topic_direction(prompts_long[i])
                if curr_dir == "probing":
                    flip_score += 1.5
                elif prev_dir == "probing" and curr_dir == "benign":
                    flip_score += 0.3
                else:
                    flip_score += 1.0
        ldfr = min(flip_score / n_pairs, 1.0)

        # ── DIV: Short vs long window divergence ──────────────────────────
        if len(prompts_short) >= 2:
            sims_short = [
                max(_embed_sim(prompts_short[i], prompts_short[i-1]), 0.30)
                for i in range(1, len(prompts_short))
            ]
            sw = _decay_weights(len(sims_short))
            c_short = sum(w * s for w, s in zip(sw, sims_short))
        else:
            c_short = c_consistency

        divergence = max(0.0, c_consistency - c_short)

        # ── BURST: Timing anomaly ─────────────────────────────────────────
        if len(timestamps) >= 3:
            gaps = [max(timestamps[i] - timestamps[i-1], 0)
                    for i in range(1, len(timestamps))]
            burst_frac   = sum(1 for g in gaps if g < 2.0) / len(gaps)
            recency_burst = 1.0 if gaps and gaps[-1] < 1.0 else 0.0
            burst = min(0.7 * burst_frac + 0.3 * recency_burst, 1.0)
        else:
            burst = 0.0

        # ── Per-user baseline deviation ───────────────────────────────────
        baseline_penalty = 0.0
        baseline = _get_baseline(session_id)
        if baseline and baseline.get("locked"):
            dev_c = abs(c_consistency - baseline["mean_c"])
            dev_b = abs(b_boundaries  - baseline["mean_b"])
            baseline_penalty = min((dev_c + dev_b) * 0.5, 0.30)
        elif not blocked:
            obs = _kv_get(f"asi:baseline_obs:{session_id}", [])
            obs.append({"c": round(c_consistency, 4), "b": round(b_boundaries, 4)})
            obs = obs[-LONG_WINDOW:]
            _kv_set(f"asi:baseline_obs:{session_id}", obs)
            if len(obs) >= BASELINE_MIN_OBS and not (baseline and baseline.get("locked")):
                mc = sum(o["c"] for o in obs) / len(obs)
                mb = sum(o["b"] for o in obs) / len(obs)
                _set_baseline(session_id, {
                    "locked": True,
                    "mean_c": round(mc, 4),
                    "mean_b": round(mb, 4),
                    "n_obs": len(obs),
                })

        # ── ASI fusion ────────────────────────────────────────────────────
        raw_asi = (
            0.30 * c_consistency
            + 0.25 * t_tool
            + 0.20 * b_boundaries
            + 0.15 * (1.0 - ldfr)
            + 0.05 * (1.0 - divergence)
            + 0.05 * (1.0 - burst)
        ) - baseline_penalty

        # Multiplicative co-firing penalty
        signals_firing = sum([
            c_consistency < 0.50,
            ldfr > 0.30,
            burst > 0.40,
            divergence > 0.30,
            t_tool < 0.75,
        ])
        if signals_firing >= 3:
            raw_asi *= 0.80
        elif signals_firing >= 2:
            raw_asi *= 0.92

        asi = round(max(0.0, min(1.0, raw_asi)), 4)

        # ── Soft suspicion with decay ─────────────────────────────────────
        suspicion = _get_suspicion(session_id)
        if asi < ALERT_THRESHOLD:
            deficit = ALERT_THRESHOLD - asi
            suspicion += 0.5 + deficit * 2.0
        else:
            suspicion = max(0.0, suspicion - SUSPICION_DECAY)
        _set_suspicion(session_id, suspicion)

        alert = suspicion >= SUSPICION_ALERT

        # ── Orchestrator modulation hints ─────────────────────────────────
        ml_tighten = 0.0
        if suspicion >= SUSPICION_ALERT:
            ml_tighten = round(min(0.15, (suspicion - SUSPICION_ALERT) * 0.05), 4)

        require_reverify = (
            alert
            and tool_invoked is not None
            and _topic_direction(prompt) == "probing"
        )

        return ASISnapshot(
            session_id=session_id,
            asi=asi,
            c_consistency=round(c_consistency, 4),
            t_tool=round(t_tool, 4),
            b_boundaries=round(b_boundaries, 4),
            ldfr=round(ldfr, 4),
            divergence=round(divergence, 4),
            burst=round(burst, 4),
            suspicion=round(suspicion, 4),
            alert=alert,
            window_count=len(history),
            ml_threshold_tighten=ml_tighten,
            require_token_reverify=require_reverify,
        )

    def get_risk_score(self, session_id: str) -> float:
        """Returns inverted ASI as a risk score (0 = safe, 1 = high risk)."""
        history = _get_session(session_id)
        if not history:
            return 0.0
        snap = self.compute(
            prompt=history[-1]["prompt"],
            session_id=session_id,
        )
        return round(1.0 - snap.asi, 4)

    def get_ml_threshold_delta(self, session_id: str) -> float:
        """
        Returns a positive delta by which the orchestrator should tighten
        ML thresholds for this session. 0.0 = no change.
        """
        suspicion = _get_suspicion(session_id)
        if suspicion < SUSPICION_ALERT:
            return 0.0
        return round(min(0.15, (suspicion - SUSPICION_ALERT) * 0.05), 4)

    def reset_session(self, session_id: str):
        """Clear session history (e.g. after a legitimate context reset)."""
        _save_session(session_id, [])
        _set_suspicion(session_id, 0.0)
