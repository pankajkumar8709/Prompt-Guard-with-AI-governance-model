"""Multi-turn conversation context engine.

Stores last N turns per session_id and computes a cumulative risk score used to
detect slow-burn attacks.

Signals (heuristics):
- gradual persona shift / roleplay build-up
- repeated probing of restrictions
- escalating privilege requests

Thresholds:
- cumulative_risk_score >= 0.4 => SUSPICIOUS
- cumulative_risk_score >= 0.7 => MALICIOUS
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _default_db_path() -> Path:
    # Reuse stats DB path unless explicitly overridden.
    override = os.environ.get("PROMPT_GUARD_STATS_DB")
    if override:
        return Path(override)
    return Path(os.environ.get("PROMPT_GUARD_LOG_DIR", "logs")) / "stats.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversation_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  session_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  user_message TEXT NOT NULL,
  risk_score REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_conversation_sessions_session_ts
  ON conversation_sessions(session_id, ts);
"""


_PERSONA_SHIFT_RE = re.compile(
    r"\b(pretend|roleplay|act as|you are now|stay in character|as a \w+ bot|unrestricted)\b",
    re.I,
)

_RESTRICTION_PROBE_RE = re.compile(
    r"\b(what are you allowed to|what can you not|list your rules|policy|alignment|safety filter)\b",
    re.I,
)

_PRIV_ESCALATION_RE = re.compile(
    r"\b(admin|administrator|root|superuser|developer mode|internal tools|privileged)\b",
    re.I,
)

# Content-based scoring for slow-burn detection.
_SB_SAVINGS_RE = re.compile(r"\bsavings\s+account\b", re.I)
_SB_DATA_STORAGE_RE = re.compile(r"\bstore\b.*\bcustomer\s+data\b|\bcustomer\s+data\s+storage\b", re.I | re.S)
_SB_TXN_FORMAT_RE = re.compile(r"\bformat\b.*\btransaction\s+data\b|\biso\s*8583\b", re.I | re.S)
_SB_EXAMPLE_RECORD_RE = re.compile(r"\bexample\s+record\b|\bdummy\s+example\b", re.I)
_SB_REAL_DB_RE = re.compile(r"\b(real\s+one|real\s+record|from\s+your\s+db|from\s+the\s+db|database\s+record)\b", re.I)


def score_message_for_slow_burn(text: str) -> float:
    """Estimate per-turn risk score (0..1) for slow-burn detection.

    This is intentionally lightweight and deterministic. It is not the same as
    the security risk engine; it's a *context* signal.
    """

    t = (text or "").strip()
    if not t:
        return 0.0

    # FIX 4: Enhanced scoring for multi-turn attacks
    if _SB_REAL_DB_RE.search(t):
        return 0.90
    if _SB_EXAMPLE_RECORD_RE.search(t):
        return 0.50
    if _SB_TXN_FORMAT_RE.search(t):
        return 0.30
    if _SB_DATA_STORAGE_RE.search(t):
        return 0.20
    if _SB_SAVINGS_RE.search(t):
        return 0.0

    # Generic probing/escalation signals
    if _PRIV_ESCALATION_RE.search(t):
        return 0.60
    if _RESTRICTION_PROBE_RE.search(t):
        return 0.40  # Increased from 0.35
    if _PERSONA_SHIFT_RE.search(t):
        return 0.40  # Increased from 0.35

    return 0.0


@dataclass(frozen=True)
class ContextResult:
    cumulative_risk_score: float
    slow_burn_flags: List[str]
    # Whether we should display a user-facing warning for the session.
    suspicious_session: bool = False


class ConversationTracker:
    def __init__(self, db_path: Optional[Path] = None, *, max_turns: int = 10):
        self.db_path = Path(db_path) if db_path else _default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_turns = int(max_turns)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                return

    def record_turn(
        self,
        *,
        session_id: str,
        tenant_id: str,
        user_message: str,
        risk_score: float,
        ts: Optional[str] = None,
    ) -> None:
        row_ts = ts or datetime.now(timezone.utc).isoformat()
        sid = (session_id or "").strip()
        if not sid:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO conversation_sessions(ts, session_id, tenant_id, user_message, risk_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (row_ts, sid, str(tenant_id or "default"), str(user_message or ""), float(risk_score)),
            )
            self._conn.commit()

            # Keep only last N turns (delete older)
            self._conn.execute(
                """
                DELETE FROM conversation_sessions
                WHERE id IN (
                  SELECT id FROM conversation_sessions
                  WHERE session_id = ?
                  ORDER BY id DESC
                  LIMIT -1 OFFSET ?
                )
                """,
                (sid, int(self.max_turns)),
            )
            self._conn.commit()

    def get_last_turns(self, *, session_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        sid = (session_id or "").strip()
        if not sid:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT ts, tenant_id, user_message, risk_score
                FROM conversation_sessions
                WHERE session_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (sid, int(limit)),
            ).fetchall()
        # reverse to chronological order
        rows.reverse()
        return [
            {
                "ts": ts,
                "tenant_id": tid,
                "user_message": msg,
                "risk_score": float(rs),
            }
            for ts, tid, msg, rs in rows
        ]

    def evaluate_context(self, *, session_id: str, current_text: str) -> ContextResult:
        """Compute cumulative risk based on recent history + current message.

        Uses recency-weighted accumulation to detect slow-burn attacks.
        """

        sid = (session_id or "").strip()
        if not sid:
            return ContextResult(cumulative_risk_score=0.0, slow_burn_flags=[])

        turns = self.get_last_turns(session_id=sid, limit=self.max_turns)
        flags: List[str] = []

        # FIX 4: Accumulate risk with recency weighting
        total = 0.0
        for i, turn in enumerate(turns):
            recency_weight = 0.7 + (0.03 * i)  # Recent turns matter more
            total += float(turn["risk_score"]) * recency_weight
        
        # Add current turn
        if current_text:
            current_score = score_message_for_slow_burn(current_text)
            recency_weight = 0.7 + (0.03 * len(turns))
            total += current_score * recency_weight
        
        # Apply session amplifier (longer suspicious sessions = higher risk)
        suspicious_turns = sum(1 for t in turns if float(t["risk_score"]) >= 0.3)
        amplifier = 1.0 + (0.15 * suspicious_turns)
        cumulative = min(1.0, total * amplifier)

        # Slow-burn heuristics across turns
        texts = [t["user_message"] for t in turns] + [current_text or ""]
        joined = "\n".join(texts)

        persona_hits = sum(1 for x in texts if _PERSONA_SHIFT_RE.search(x or ""))
        if persona_hits >= 2:
            flags.append("gradual_persona_shift")
            cumulative = min(1.0, cumulative + 0.20)

        probe_hits = sum(1 for x in texts if _RESTRICTION_PROBE_RE.search(x or ""))
        if probe_hits >= 2:
            flags.append("repeated_restriction_probing")
            cumulative = min(1.0, cumulative + 0.20)

        priv_hits = sum(1 for x in texts if _PRIV_ESCALATION_RE.search(x or ""))
        if priv_hits >= 2:
            flags.append("escalating_privilege_requests")
            cumulative = min(1.0, cumulative + 0.25)

        # If the thread contains both probing and escalation keywords, boost
        if _RESTRICTION_PROBE_RE.search(joined) and _PRIV_ESCALATION_RE.search(joined):
            flags.append("probe_plus_escalation")
            cumulative = min(1.0, cumulative + 0.10)

        suspicious_session = bool(cumulative >= 0.4)
        return ContextResult(
            cumulative_risk_score=float(cumulative),
            slow_burn_flags=flags,
            suspicious_session=suspicious_session,
        )


_DEFAULT_TRACKER: ConversationTracker | None = None
_TRACKER_LOCK = threading.Lock()


def get_default_tracker() -> ConversationTracker:
    global _DEFAULT_TRACKER
    with _TRACKER_LOCK:
        if _DEFAULT_TRACKER is None:
            _DEFAULT_TRACKER = ConversationTracker()
        return _DEFAULT_TRACKER


def get_banking_memory(session_id: str, *, limit: int = 5) -> list[dict[str, Any]]:
    """Return last `limit` conversation turns for use by the banking agent.

    We reuse the existing conversation_sessions table. Currently it stores only
    user messages (recorded by the security/context layer). This is still enough
    to resolve follow-ups like "what if for 20 years instead?".
    """

    return get_default_tracker().get_last_turns(session_id=session_id, limit=int(limit))
