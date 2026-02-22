import asyncio
import re

import pytest

from prompt_guard_gateway.banking_knowledge_agent import banking_knowledge_agent
from prompt_guard_gateway.domain_filter import DomainScope, DomainScopeFilter


def test_dynamic_emi_calculation_structured():
    r = asyncio.run(
        banking_knowledge_agent.ainvoke(
        {
            "query": "EMI for ₹23.5 lakh at 8.75% for 17 years?",
            "conversation_history": {"turns": []},
            "session_id": "t1",
        }
        )
    )
    assert r.response_type == "CALCULATION"
    # should contain a numeric EMI and rupee symbol
    assert "₹" in r.answer
    assert re.search(r"EMI.*₹[0-9,]+\.[0-9]{2}", r.answer, re.I | re.S)


def test_emergency_detection_prefix_and_1930():
    r = asyncio.run(
        banking_knowledge_agent.ainvoke(
        {
            "query": "Someone called claiming to be from bank and I shared my OTP",
            "conversation_history": {"turns": []},
            "session_id": "t2",
        }
        )
    )
    assert r.response_type == "EMERGENCY"
    assert r.urgency is True
    assert "1930" in r.answer or "cybercrime" in r.answer.lower()
    assert "IMMEDIATE ACTION" in r.answer


def test_multi_turn_context_followup_recomputes_years():
    # Turn 1 stored in history
    hist = {
        "turns": [
            {
                "ts": "2026-01-01T00:00:00Z",
                "tenant_id": "default",
                "user_message": "What is the EMI for ₹10 lakh loan at 9%?",
                "risk_score": 0.0,
            }
        ]
    }
    r = asyncio.run(
        banking_knowledge_agent.ainvoke(
        {
            "query": "What if I take it for 20 years instead?",
            "conversation_history": hist,
            "session_id": "t3",
        }
        )
    )
    # With context injection, we should still produce a calculation answer.
    assert r.response_type in {"CALCULATION", "GENERAL"}
    assert "₹" in r.answer


def test_hard_boundary_requires_auth_domain_filter_prevents_call():
    f = DomainScopeFilter()
    r = f.classify("What is my account balance?")
    assert r.scope == DomainScope.REQUIRES_AUTH


def test_process_guidance_ombudsman_steps():
    r = asyncio.run(
        banking_knowledge_agent.ainvoke(
        {
            "query": "How to file Banking Ombudsman complaint?",
            "conversation_history": {"turns": []},
            "session_id": "t4",
        }
        )
    )
    assert r.response_type in {"PROCESS", "REGULATORY"}
    # step-by-step markers
    assert "1" in r.answer and "2" in r.answer


def test_regulatory_dicgc_limit_5_lakh():
    r = asyncio.run(
        banking_knowledge_agent.ainvoke(
        {
            "query": "What is DICGC insurance limit?",
            "conversation_history": {"turns": []},
            "session_id": "t5",
        }
        )
    )
    assert r.response_type == "REGULATORY"
    assert "₹5" in r.answer and "lakh" in r.answer.lower()
