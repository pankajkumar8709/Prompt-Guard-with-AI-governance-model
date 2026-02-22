"""Simplified 3-Node Security Agent using Groq"""

from langgraph.graph import StateGraph, END
from typing import TypedDict
import os
import logging

from .banking_knowledge_agent import banking_agent
from .stats import StatsCollector

# Security layer: self-governance (new) or legacy 7-layer pipeline
if os.getenv("USE_SELF_GOVERNANCE", "false").lower() == "true":
    from .self_governance_engine import analyze
    _security_backend = "self_governance"
else:
    from .groq_security_agent import analyze
    _security_backend = "legacy"

# Re-export for /classify and other callers
__all__ = ["agent", "analyze"]

logger = logging.getLogger(__name__)

class AgentState(TypedDict):
    user_input: str
    session_id: str
    tenant_id: str
    history: list
    security_result: dict
    final_response: str
    inference_ms: float

BLOCK_RESPONSES = {
    "JAILBREAK":           "Request blocked: jailbreak attempt detected.",
    "SYSTEM_OVERRIDE":     "Request blocked: system override attempt detected.",
    "DATA_EXTRACTION":     "Request blocked: data extraction attempt detected. Incident logged.",
    "SOCIAL_ENGINEERING":  "Request blocked: social engineering attempt detected.",
    "INSTRUCTION_CHAINING":"Request blocked: instruction chaining detected.",
    "FAST_RULE":           "Request blocked: known attack pattern detected.",
    "NONE":                "Request blocked by security filter.",
}

SCOPE_RESPONSES = {
    "REQUIRES_AUTH": (
        "This requires account authentication. "
        "Please log in to your banking app or call 1800-XXX-XXXX."
    ),
    "OUT_OF_SCOPE": (
        "I'm a banking assistant and can only help with banking "
        "and finance queries. How can I help you with banking today?"
    ),
}

async def node_analyze(state: AgentState) -> AgentState:
    """Security analysis node."""
    try:
        result = analyze(
            state["user_input"],
            state["session_id"],
            state.get("history", [])
        )
        state["security_result"] = result
    except Exception as e:
        logger.error(f"node_analyze error: {e}")
        state["security_result"] = {
            "classification": "SAFE",
            "action": "ALLOW",
            "domain_scope": "IN_SCOPE",
            "attack_type": "NONE",
            "reasoning": "error fallback",
            "explanation": "",
            "risk_score": 0.0,
            "inference_ms": 0.0
        }
    return state

async def node_respond(state: AgentState) -> AgentState:
    """Response generation node."""
    try:
        result = state["security_result"]
        action = result.get("action", "ALLOW")
        scope = result.get("domain_scope", "IN_SCOPE")
        attack = result.get("attack_type", "NONE")

        if action == "BLOCK" or result.get("classification") == "MALICIOUS":
            state["final_response"] = BLOCK_RESPONSES.get(attack, BLOCK_RESPONSES["NONE"])

        elif scope in SCOPE_RESPONSES:
            state["final_response"] = SCOPE_RESPONSES[scope]

        else:
            # SAFE + IN_SCOPE → banking agent
            response_obj = await banking_agent.ainvoke({
                "query": state["user_input"],
                "session_id": state["session_id"]
            })
            state["final_response"] = response_obj.answer

            # Update history with this safe exchange
            history = state.get("history", [])
            history.append({"role": "user",
                           "content": state["user_input"],
                           "risk_score": result.get("risk_score", 0.0)})
            history.append({"role": "assistant",
                           "content": state["final_response"],
                           "risk_score": 0.0})
            state["history"] = history[-20:]

    except Exception as e:
        logger.error(f"node_respond error: {e}")
        state["final_response"] = (
            "Unable to process request. Call 1800-XXX-XXXX for help."
        )
    return state

async def node_log(state: AgentState) -> AgentState:
    """Logging node — never blocks response."""
    try:
        stats = StatsCollector.get_instance()
        result = state["security_result"]
        stats.log_request(
            tenant_id=state.get("tenant_id", "default"),
            label=result.get("classification", "UNKNOWN"),
            confidence=result.get("confidence", 0.0),
            filter_stage="groq_agent",
            is_safe=result.get("action") != "BLOCK",
            text_length=len(state["user_input"]),
            risk_level=result.get("classification", "SAFE"),
            attack_types=result.get("attack_type", "NONE"),
            enforcement_action=result.get("action", "ALLOW"),
            session_id=state.get("session_id"),
            cumulative_risk_score=result.get("risk_score", 0.0),
            inference_ms=result.get("inference_ms", 0.0)
        )
    except Exception as e:
        logger.error(f"node_log error: {e}")
    return state

# Build graph
graph = StateGraph(AgentState)
graph.add_node("analyze", node_analyze)
graph.add_node("respond", node_respond)
graph.add_node("log", node_log)
graph.set_entry_point("analyze")
graph.add_edge("analyze", "respond")
graph.add_edge("respond", "log")
graph.add_edge("log", END)
agent = graph.compile()
