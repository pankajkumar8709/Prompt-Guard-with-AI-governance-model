"""LangChain tool wrappers for the security gateway modules.

Nothing in the existing pipeline is deleted; these tools are thin adapters
around the existing modules so a LangGraph agent can orchestrate them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import httpx
from langchain_core.tools import tool

from . import tenant_config
from .attack_classifier import AttackType, classify_attack_types
from .banking_responder import BankingResponder
from .context_engine import get_default_tracker, score_message_for_slow_burn
from .domain_filter import DomainScopeFilter
from .enforcer import EnforcementAction, enforce, sanitize_text
from .explainer import generate_explanation as _generate_explanation
from .explainer import highlight_risky_segments
from .guard import ClassificationResult
from .risk_engine import RiskLevel, evaluate_risk
from .stats import StatsCollector

# Import gateway module functions so tests that monkeypatch
# prompt_guard_gateway.gateway.* still affect agent execution.
from . import gateway as gateway_mod


_scope_filter = DomainScopeFilter()
_banking_responder = BankingResponder()


@tool
def classify_risk(text: str, tenant_id: str = "default") -> dict:
    """Classify prompt risk level: SAFE, SUSPICIOUS, or MALICIOUS with confidence score."""
    # We intentionally keep this lightweight; risk_engine will call Prompt-Guard
    # if no classification is injected.
    cfg = tenant_config.load_tenant_config(tenant_id)
    # Use gateway_mod.classify_prompt so existing tests can monkeypatch it.
    classification = gateway_mod.classify_prompt(text)
    segs = highlight_risky_segments(text)
    risk = evaluate_risk(
        text,
        classification=classification,
        attack_types=[],
        flagged_segments=segs,
        injection_low_confidence_cutoff=float(cfg.injection_threshold),
    )
    return {
        "label": classification.label,
        "level": risk.level.value,
        "confidence": float(risk.confidence),
        "flagged_segments": [
            {"segment": s.segment, "reason": s.reason, "risk_score": float(s.risk_score)}
            for s in risk.flagged_segments
        ],
    }


@tool
def detect_attack_type(text: str) -> dict:
    """Detect attack types: JAILBREAK, SYSTEM_PROMPT_OVERRIDE, DATA_EXTRACTION, INSTRUCTION_CHAINING."""
    atk = classify_attack_types(text)
    return {
        "attack_types": [a.value for a in atk.attack_types],
        "scores": {k.value: float(v) for k, v in (atk.scores or {}).items()},
    }


@tool
def get_conversation_history(session_id: str) -> dict:
    """Retrieve last 10 turns and cumulative risk score for this session."""
    turns = get_default_tracker().get_last_turns(session_id=session_id, limit=10)
    # produce a cumulative score consistent with context engine
    cum = 0.0
    for t in turns:
        cum += float(t.get("risk_score") or 0.0)
    cumulative_risk_score = 1.0 - (1.0 / (1.0 + cum)) if turns else 0.0
    return {"turns": turns, "cumulative_risk_score": float(cumulative_risk_score)}


@tool
def update_session_risk(session_id: str, turn_risk_score: float, user_message: str = "", tenant_id: str = "default") -> dict:
    """Update cumulative session risk score and detect slow-burn attack patterns."""
    # Persist turn
    if session_id:
        get_default_tracker().record_turn(
            session_id=session_id,
            tenant_id=tenant_id,
            user_message=user_message,
            risk_score=float(turn_risk_score),
        )
        ctx = get_default_tracker().evaluate_context(session_id=session_id, current_text=user_message)
        return {
            "cumulative_risk_score": float(ctx.cumulative_risk_score),
            "slow_burn_flags": list(ctx.slow_burn_flags),
            "suspicious_session": bool(ctx.suspicious_session),
        }
    return {"cumulative_risk_score": 0.0, "slow_burn_flags": [], "suspicious_session": False}


@tool
def check_domain_scope(text: str) -> dict:
    """Classify query as IN_SCOPE, OUT_OF_SCOPE, or REQUIRES_AUTH."""
    res = _scope_filter.classify(text)
    return {"scope": res.scope.value, "confidence": float(res.confidence), "reasons": list(res.reasons)}


@tool
def enforce_action(risk_level: str, attack_types: list, tenant_id: str = "default") -> dict:
    """Decide enforcement: BLOCK, WARN, SANITIZE, or ALLOW based on risk and tenant config."""
    cfg = tenant_config.load_tenant_config(tenant_id)
    # Minimal RiskResult-like dict -> map to RiskLevel
    rl = RiskLevel(str(risk_level).lower()) if str(risk_level).lower() in {"safe", "suspicious", "malicious"} else RiskLevel.SUSPICIOUS
    if rl == RiskLevel.SAFE:
        action = EnforcementAction.ALLOW
    elif rl == RiskLevel.MALICIOUS:
        action = EnforcementAction.BLOCK
    else:
        action = EnforcementAction.WARN if (cfg.suspicious_action or "sanitize").lower() == "warn" else EnforcementAction.SANITIZE
    # promote to block if jailbreak
    if "JAILBREAK" in [str(a) for a in (attack_types or [])]:
        action = EnforcementAction.BLOCK
    return {"action": action.value, "suspicious_action": cfg.suspicious_action}


@tool
def sanitize_prompt(text: str, flagged_segments: list) -> str:
    """Remove flagged segments from prompt and return cleaned version."""
    # flagged_segments expected to be list of dicts or list of FlaggedSegment-like objects
    segs = []
    for s in flagged_segments or []:
        if isinstance(s, dict):
            segs.append(type("FS", (), {"segment": s.get("segment", "")}))
        else:
            segs.append(s)
    return sanitize_text(text, segs)  # type: ignore[arg-type]


@tool
def generate_explanation(risk_result: dict, conversation_history: dict | None = None) -> str:
    """Generate natural language explanation of why this prompt was flagged."""
    # Create a minimal RiskResult compatible object.
    # We only need .level/.attack_types/.flagged_segments/.is_safe.
    lvl = str(risk_result.get("level") or "safe").lower()
    rl = RiskLevel(lvl) if lvl in {"safe", "suspicious", "malicious"} else RiskLevel.SUSPICIOUS
    atk = list(risk_result.get("attack_types") or [])
    segs = risk_result.get("flagged_segments") or []
    # Build RiskResult via evaluate_risk but override level/attack types to keep output deterministic.
    rr = evaluate_risk(
        str(risk_result.get("text") or ""),
        classification=ClassificationResult("BENIGN", float(risk_result.get("confidence") or 1.0)),
        attack_types=atk,
        flagged_segments=[
            type("FS", (), {"segment": s.get("segment"), "reason": s.get("reason"), "risk_score": float(s.get("risk_score") or 0.0)})
            for s in segs
            if isinstance(s, dict)
        ],
    )
    rr = rr.__class__(
        level=rl,
        attack_types=rr.attack_types,
        confidence=rr.confidence,
        explanation=rr.explanation,
        flagged_segments=rr.flagged_segments,
        cumulative_risk_score=float(risk_result.get("cumulative_risk_score") or 0.0),
    )
    return _generate_explanation(rr)


@tool
def get_banking_response(intent: str | None, query: str) -> str:
    """Generate appropriate banking response for in-scope queries."""
    # intent is ignored; BankingResponder will re-detect.
    # Keep template-based responder behavior in tests; but allow
    # downstream to be swapped by agent if desired.
    from .groq_llm import groq_llm

    br = _banking_responder.respond(query, downstream_llm=groq_llm)
    return br.response


@tool
def log_incident(
    risk_result: dict,
    action: str,
    tenant_id: str = "default",
    session_id: str | None = None,
    filter_stage: str = "agent",
    inference_ms: float | None = None,
) -> bool:
    """Log security incident to SQLite and flagged.log with full audit trail."""
    stats = StatsCollector.get_instance()
    label = str(risk_result.get("label") or "BENIGN")
    conf = float(risk_result.get("confidence") or 1.0)
    risk_level = str(risk_result.get("level") or "safe")
    attack_types = json.dumps(list(risk_result.get("attack_types") or []), ensure_ascii=False)
    cumulative = float(risk_result.get("cumulative_risk_score") or 0.0)
    stats.log_request(
        tenant_id=str(tenant_id or "default"),
        label=label,
        confidence=conf,
        filter_stage=filter_stage,
        is_safe=(str(action).upper() != "BLOCK"),
        text_length=int(risk_result.get("text_length") or 0),
        risk_level=risk_level,
        attack_types=attack_types,
        enforcement_action=str(action).upper(),
        session_id=session_id,
        cumulative_risk_score=cumulative,
        inference_ms=float(inference_ms) if inference_ms is not None else None,
    )
    return True


@tool
async def send_webhook_alert(tenant_id: str, risk_result: dict) -> bool:
    """Send async webhook alert for JAILBREAK detections."""
    url = os.environ.get("ALERT_WEBHOOK_URL")
    if not url:
        return False
    payload = {
        "tenant_id": tenant_id,
        "risk_level": risk_result.get("level"),
        "attack_types": risk_result.get("attack_types"),
        "ts": risk_result.get("ts"),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(url, json=payload)
        return True
    except Exception:
        return False


def ensure_incident_dirs() -> Path:
    d = Path(os.environ.get("PROMPT_GUARD_LOG_DIR", "logs")) / "incidents"
    d.mkdir(parents=True, exist_ok=True)
    return d
