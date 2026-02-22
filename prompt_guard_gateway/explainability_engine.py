"""Explainable Security Decisions - Multi-layered transparency without exposing internals"""

import re
from typing import Dict, List, Optional

# Rule catalog (sanitized for external exposure)
RULE_CATALOG = {
    "RULE_01": "Instruction override detection",
    "RULE_02": "System prompt extraction attempt",
    "RULE_03": "Privilege escalation pattern",
    "RULE_04": "Database query injection",
    "RULE_05": "Bulk data extraction request",
    "RULE_06": "Identity manipulation attempt",
    "RULE_07": "Security bypass command",
    "RULE_08": "Jailbreak mode activation",
    "RULE_09": "Developer mode exploitation",
    "RULE_10": "Encoded payload detection",
    "RULE_11": "Social engineering tactics",
    "RULE_12": "Multi-step attack chain",
    "RULE_13": "Session escalation pattern",
    "RULE_14": "Threat memory match",
    "RULE_15": "Context-based risk accumulation",
}

# Attack type descriptions
ATTACK_DESCRIPTIONS = {
    "JAILBREAK": "Attempt to bypass AI safety guidelines",
    "SYSTEM_OVERRIDE": "Attempt to override system instructions",
    "DATA_EXTRACTION": "Attempt to extract unauthorized data",
    "SOCIAL_ENGINEERING": "Deceptive tactics to gain unauthorized access",
    "INSTRUCTION_CHAINING": "Multi-step manipulation sequence",
    "FAST_RULE": "Known attack pattern detected",
    "NONE": "No security threat detected",
}

# Risk factor templates
RISK_FACTORS = {
    "instruction_override": "Contains instruction override phrases",
    "privilege_escalation": "Attempts privilege escalation",
    "data_dump": "Requests bulk data access",
    "identity_manipulation": "Attempts identity manipulation",
    "security_bypass": "Attempts to bypass security controls",
    "jailbreak_keywords": "Contains jailbreak activation keywords",
    "encoded_payload": "Contains encoded or obfuscated content",
    "social_engineering": "Uses social engineering tactics",
    "session_escalation": "Gradual escalation across conversation",
    "threat_memory": "Matches known attack patterns",
    "context_risk": "Cumulative risk from conversation history",
}


def detect_triggered_rules(text: str, attack_type: str, memory_match: bool, session_risk: float) -> List[str]:
    """Identify which rules were triggered (without exposing exact patterns)."""
    rules = []
    t = text.lower()
    
    # Pattern-based rules (sanitized)
    if re.search(r"ignore|forget|disregard", t) and re.search(r"instruction|prompt|rule", t):
        rules.append("RULE_01")
    
    if re.search(r"reveal|show|print|display", t) and re.search(r"prompt|instruction|system", t):
        rules.append("RULE_02")
    
    if re.search(r"admin|developer|root|sudo|override", t):
        rules.append("RULE_03")
    
    if re.search(r"select\s+\*|dump|database|sql", t):
        rules.append("RULE_04")
    
    if re.search(r"all\s+(users?|customers?|accounts?|records?|data)", t):
        rules.append("RULE_05")
    
    if re.search(r"(pretend|act|assume|imagine).+(you|i).+(am|are)", t):
        rules.append("RULE_06")
    
    if re.search(r"disable|bypass|remove.+(security|filter|restriction)", t):
        rules.append("RULE_07")
    
    if re.search(r"jailbreak|dan|unrestricted", t):
        rules.append("RULE_08")
    
    if re.search(r"developer\s+mode|debug\s+mode|test\s+mode", t):
        rules.append("RULE_09")
    
    if re.search(r"base64|encode|decode|\\x[0-9a-f]{2}", t):
        rules.append("RULE_10")
    
    # Attack type rules
    if attack_type == "SOCIAL_ENGINEERING":
        rules.append("RULE_11")
    
    if attack_type == "INSTRUCTION_CHAINING":
        rules.append("RULE_12")
    
    # Context rules
    if session_risk > 0.4:
        rules.append("RULE_13")
    
    if memory_match:
        rules.append("RULE_14")
    
    if session_risk > 0.6:
        rules.append("RULE_15")
    
    return list(set(rules))  # Remove duplicates


def extract_risk_factors(text: str, attack_type: str, rules: List[str], memory_match: bool) -> List[str]:
    """Extract human-readable risk factors."""
    factors = []
    
    # Map rules to risk factors
    rule_factor_map = {
        "RULE_01": "instruction_override",
        "RULE_02": "instruction_override",
        "RULE_03": "privilege_escalation",
        "RULE_04": "data_dump",
        "RULE_05": "data_dump",
        "RULE_06": "identity_manipulation",
        "RULE_07": "security_bypass",
        "RULE_08": "jailbreak_keywords",
        "RULE_09": "jailbreak_keywords",
        "RULE_10": "encoded_payload",
        "RULE_11": "social_engineering",
        "RULE_12": "social_engineering",
        "RULE_13": "session_escalation",
        "RULE_14": "threat_memory",
        "RULE_15": "context_risk",
    }
    
    for rule in rules:
        factor_key = rule_factor_map.get(rule)
        if factor_key and factor_key not in [f.split(":")[0] for f in factors]:
            factors.append(RISK_FACTORS[factor_key])
    
    return factors


def generate_technical_explanation(
    decision: str,
    attack_type: str,
    rules: List[str],
    confidence: float,
    risk_score: float,
    memory_similarity: float
) -> str:
    """Generate technical explanation for developers/security teams."""
    parts = [f"Decision: {decision}"]
    
    if attack_type != "NONE":
        parts.append(f"Threat Type: {attack_type} - {ATTACK_DESCRIPTIONS.get(attack_type, 'Unknown')}")
    
    if rules:
        rule_names = [f"{r} ({RULE_CATALOG.get(r, 'Unknown')})" for r in rules]
        parts.append(f"Triggered Rules: {', '.join(rule_names)}")
    
    parts.append(f"Confidence: {confidence:.2f}")
    parts.append(f"Risk Score: {risk_score:.2f}")
    
    if memory_similarity > 0:
        parts.append(f"Threat Memory Match: {memory_similarity:.2f}")
    
    return " | ".join(parts)


def generate_user_explanation(decision: str, attack_type: str, domain_scope: str) -> str:
    """Generate safe, user-friendly explanation (never reveals internals)."""
    if decision == "BLOCK":
        if attack_type in ["JAILBREAK", "SYSTEM_OVERRIDE"]:
            return "Your request cannot be processed as it appears to contain instructions that conflict with our security policies."
        elif attack_type == "DATA_EXTRACTION":
            return "Your request cannot be processed as it requests access to data that requires proper authentication."
        elif attack_type == "SOCIAL_ENGINEERING":
            return "Your request cannot be processed. Please contact customer support if you need assistance."
        else:
            return "Your request cannot be processed due to security policies. Please rephrase your question."
    
    elif decision == "WARN":
        return "Your request has been flagged for review. Please ensure you're following proper authentication procedures."
    
    elif decision == "ALLOW":
        if domain_scope == "REQUIRES_AUTH":
            return "This request requires authentication. Please log in to access your account information."
        elif domain_scope == "OUT_OF_SCOPE":
            return "This question is outside our banking services scope. How can I help you with banking today?"
        else:
            return ""  # No explanation needed for safe requests
    
    return ""


def generate_explainable_decision(
    classification: str,
    action: str,
    attack_type: str,
    domain_scope: str,
    reasoning: str,
    confidence: float,
    risk_score: float,
    text: str,
    memory_similarity: float = 0.0,
    session_risk: float = 0.0
) -> Dict:
    """
    Generate comprehensive explainable security decision.
    
    Returns multi-layered explanation without exposing system internals.
    """
    # Detect triggered rules
    memory_match = memory_similarity >= 0.85
    triggered_rules = detect_triggered_rules(text, attack_type, memory_match, session_risk)
    
    # Extract risk factors
    risk_factors = extract_risk_factors(text, attack_type, triggered_rules, memory_match)
    
    # Generate explanations
    technical_explanation = generate_technical_explanation(
        action,
        attack_type,
        triggered_rules,
        confidence,
        risk_score,
        memory_similarity
    )
    
    user_explanation = generate_user_explanation(action, attack_type, domain_scope)
    
    return {
        "decision": action,
        "security_analysis": {
            "threat_type": attack_type,
            "threat_description": ATTACK_DESCRIPTIONS.get(attack_type, "Unknown"),
            "triggered_rules": triggered_rules,
            "rule_descriptions": [RULE_CATALOG.get(r, "Unknown") for r in triggered_rules],
            "confidence_factors": risk_factors,
            "confidence_score": round(confidence, 3),
            "risk_score": round(risk_score, 3),
            "threat_memory_similarity": round(memory_similarity, 3) if memory_similarity > 0 else None,
            "session_risk_level": round(session_risk, 3) if session_risk > 0 else None,
        },
        "explanations": {
            "technical": technical_explanation,
            "user_safe": user_explanation,
            "internal_reasoning": reasoning,  # For logging only, not exposed to end users
        },
        "policy_compliance": {
            "domain_scope": domain_scope,
            "classification": classification,
            "requires_authentication": domain_scope == "REQUIRES_AUTH",
            "in_scope": domain_scope in ["IN_SCOPE", "REQUIRES_AUTH"],
        }
    }


def sanitize_for_logging(explanation: Dict) -> Dict:
    """Remove sensitive fields before logging to external systems."""
    safe_copy = explanation.copy()
    
    # Remove internal reasoning from external logs
    if "explanations" in safe_copy:
        safe_copy["explanations"] = {
            "technical": safe_copy["explanations"]["technical"],
            "user_safe": safe_copy["explanations"]["user_safe"],
            # internal_reasoning removed
        }
    
    return safe_copy
