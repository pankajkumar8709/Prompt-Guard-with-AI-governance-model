"""SQLite-backed request logging + stats aggregation.

Replaces the previous in-memory StatsCollector.

DB location:
- PROMPT_GUARD_STATS_DB=/path/to/stats.db (optional)
- default: logs/stats.db
"""

from __future__ import annotations

import csv
import os
import sqlite3
import threading
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import math


def _default_db_path() -> Path:
    override = os.environ.get("PROMPT_GUARD_STATS_DB")
    if override:
        return Path(override)
    return Path(os.environ.get("PROMPT_GUARD_LOG_DIR", "logs")) / "stats.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS request_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  label TEXT NOT NULL,
  confidence REAL NOT NULL,
  filter_stage TEXT NOT NULL,
  is_safe INTEGER NOT NULL,
  text_length INTEGER NOT NULL,

  -- Security-layer extensions (nullable for backwards compatibility)
  risk_level TEXT,
  attack_types TEXT,
  enforcement_action TEXT,
  session_id TEXT,
  cumulative_risk_score REAL,
  inference_ms REAL
);

CREATE INDEX IF NOT EXISTS idx_request_logs_ts ON request_logs(ts);
CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_ts ON request_logs(tenant_id, ts);
"""  # noqa: W291


_POST_MIGRATION_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_request_logs_session_ts ON request_logs(session_id, ts);",
]


def _ensure_column(conn: sqlite3.Connection, table: str, col: str, decl: str) -> None:
    """Add a column if missing (best-effort migration)."""

    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {r[1] for r in rows}
    if col in existing:
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def _migrate(conn: sqlite3.Connection) -> None:
    """Run lightweight schema migrations for existing DBs."""

    try:
        _ensure_column(conn, "request_logs", "risk_level", "TEXT")
        _ensure_column(conn, "request_logs", "attack_types", "TEXT")
        _ensure_column(conn, "request_logs", "enforcement_action", "TEXT")
        _ensure_column(conn, "request_logs", "session_id", "TEXT")
        _ensure_column(conn, "request_logs", "cumulative_risk_score", "REAL")
        _ensure_column(conn, "request_logs", "inference_ms", "REAL")
    except sqlite3.OperationalError:
        # If table doesn't exist yet, CREATE TABLE will cover it.
        return


class StatsCollector:
    """Thread-safe singleton around a local SQLite DB."""

    _instance: "StatsCollector | None" = None
    _instance_lock = threading.Lock()

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        _migrate(self._conn)
        # Create indexes that depend on migrated columns.
        for stmt in _POST_MIGRATION_INDEXES:
            try:
                self._conn.execute(stmt)
            except sqlite3.OperationalError:
                # Best-effort; never break startup.
                pass
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                return

    # ---- Backwards-compatible no-op increment methods (previous in-memory API) ----
    # These are kept so older code can call them safely. Real counters are derived
    # from the DB in `snapshot()`.

    def inc_total(self) -> None:  # pragma: no cover
        return

    def inc_blocked(self) -> None:  # pragma: no cover
        return

    def inc_warned(self) -> None:  # pragma: no cover
        return

    def inc_whitelist(self) -> None:  # pragma: no cover
        return

    def inc_hard_block(self) -> None:  # pragma: no cover
        return

    def inc_model_classified(self) -> None:  # pragma: no cover
        return

    @classmethod
    def get_instance(cls) -> "StatsCollector":
        desired = _default_db_path()
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = StatsCollector(db_path=desired)
            else:
                # If env changed (e.g. tests using tmp dirs), re-init.
                if Path(cls._instance.db_path) != Path(desired):
                    try:
                        cls._instance.close()
                    finally:
                        cls._instance = StatsCollector(db_path=desired)
        return cls._instance

    @classmethod
    def reset_instance_for_tests(cls) -> None:
        """Reset global singleton (useful for pytest isolation)."""
        with cls._instance_lock:
            if cls._instance is not None:
                try:
                    cls._instance.close()
                finally:
                    cls._instance = None

    def db_connected(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

    def log_request(
        self,
        *,
        tenant_id: str,
        label: str,
        confidence: float,
        filter_stage: str,
        is_safe: bool,
        text_length: int,
        # security layer extensions
        risk_level: str | None = None,
        attack_types: str | None = None,
        enforcement_action: str | None = None,
        session_id: str | None = None,
        cumulative_risk_score: float | None = None,
        inference_ms: float | None = None,
        ts: str | None = None,
    ) -> None:
        row_ts = ts or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO request_logs(
                  ts, tenant_id, label, confidence, filter_stage, is_safe, text_length,
                  risk_level, attack_types, enforcement_action, session_id, cumulative_risk_score, inference_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_ts,
                    tenant_id,
                    label,
                    float(confidence),
                    filter_stage,
                    1 if is_safe else 0,
                    int(text_length),
                    risk_level,
                    attack_types,
                    enforcement_action,
                    session_id,
                    float(cumulative_risk_score) if cumulative_risk_score is not None else None,
                    float(inference_ms) if inference_ms is not None else None,
                ),
            )
            self._conn.commit()

    def snapshot(self, *, tenant_id: str | None = None) -> dict[str, int]:
        """Aggregate counters from DB."""

        where = ""
        args: tuple[Any, ...] = ()
        if tenant_id is not None:
            where = "WHERE tenant_id = ?"
            args = (tenant_id,)

        q = f"""
        SELECT
          COUNT(*) AS total_requests,
          SUM(CASE WHEN is_safe = 0 THEN 1 ELSE 0 END) AS blocked,
          SUM(CASE WHEN (is_safe = 1 AND label = 'INJECTION') THEN 1 ELSE 0 END) AS warned,
          SUM(CASE WHEN filter_stage = 'whitelist' THEN 1 ELSE 0 END) AS whitelist_hits,
          SUM(CASE WHEN filter_stage = 'hard_block' THEN 1 ELSE 0 END) AS hard_block_hits,
          SUM(CASE WHEN filter_stage = 'model' THEN 1 ELSE 0 END) AS model_classified
        FROM request_logs
        {where}
        """

        with self._lock:
            row = self._conn.execute(q, args).fetchone()
        if row is None:
            return {
                "total_requests": 0,
                "blocked": 0,
                "warned": 0,
                "whitelist_hits": 0,
                "hard_block_hits": 0,
                "model_classified": 0,
            }
        keys = [
            "total_requests",
            "blocked",
            "warned",
            "whitelist_hits",
            "hard_block_hits",
            "model_classified",
        ]
        return {k: int(row[i] or 0) for i, k in enumerate(keys)}

    def fetch_last(
        self, *, limit: int = 1000, tenant_id: str | None = None
    ) -> list[dict[str, Any]]:
        where = ""
        args: tuple[Any, ...]
        if tenant_id is None:
            args = (int(limit),)
        else:
            where = "WHERE tenant_id = ?"
            args = (tenant_id, int(limit))

        q = f"""
        SELECT
          ts, tenant_id, label, confidence, filter_stage, is_safe, text_length,
          risk_level, attack_types, enforcement_action, session_id, cumulative_risk_score, inference_ms
        FROM request_logs
        {where}
        ORDER BY id DESC
        LIMIT ?
        """
        with self._lock:
            rows = list(self._conn.execute(q, args).fetchall())

        out: list[dict[str, Any]] = []
        for (
            ts,
            tid,
            label,
            conf,
            stage,
            is_safe,
            length,
            risk_level,
            attack_types,
            enforcement_action,
            session_id,
            cumulative_risk_score,
            inference_ms,
        ) in rows:
            out.append(
                {
                    "ts": ts,
                    "tenant_id": tid,
                    "label": label,
                    "confidence": float(conf),
                    "filter_stage": stage,
                    "is_safe": bool(is_safe),
                    "text_length": int(length),
                    "risk_level": risk_level,
                    "attack_types": attack_types,
                    "enforcement_action": enforcement_action,
                    "session_id": session_id,
                    "cumulative_risk_score": float(cumulative_risk_score)
                    if cumulative_risk_score is not None
                    else None,
                    "inference_ms": float(inference_ms) if inference_ms is not None else None,
                }
            )
        return out

    def performance_metrics(self, *, limit: int = 1000) -> dict[str, float]:
        """Return avg/p95/p99 inference times from last N requests."""

        with self._lock:
            rows = self._conn.execute(
                """
                SELECT inference_ms
                FROM request_logs
                WHERE inference_ms IS NOT NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()

        vals = [float(r[0]) for r in rows if r and r[0] is not None]
        if not vals:
            return {"avg_inference_ms": 0.0, "p95_inference_ms": 0.0, "p99_inference_ms": 0.0}

        vals.sort()
        n = len(vals)
        avg = sum(vals) / n

        def pct(p: float) -> float:
            if n == 1:
                return vals[0]
            # nearest-rank
            k = max(0, min(n - 1, int(math.ceil((p / 100.0) * n)) - 1))
            return float(vals[k])

        return {
            "avg_inference_ms": float(avg),
            "p95_inference_ms": pct(95.0),
            "p99_inference_ms": pct(99.0),
        }

    def export_last_csv(self, *, limit: int = 1000, tenant_id: str | None = None) -> str:
        rows = self.fetch_last(limit=limit, tenant_id=tenant_id)
        buf = StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "ts",
                "tenant_id",
                "label",
                "confidence",
                "filter_stage",
                "is_safe",
                "text_length",
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
        return buf.getvalue()

    def list_tenants(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT tenant_id FROM request_logs ORDER BY tenant_id"
            ).fetchall()
        return [r[0] for r in rows]

    def label_distribution(self, *, tenant_id: str | None = None) -> dict[str, int]:
        where = ""
        args: tuple[Any, ...] = ()
        if tenant_id is not None:
            where = "WHERE tenant_id = ?"
            args = (tenant_id,)

        q = f"""
        SELECT label, COUNT(*)
        FROM request_logs
        {where}
        GROUP BY label
        """
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = {"BENIGN": 0, "INJECTION": 0, "JAILBREAK": 0}
        for label, cnt in rows:
            out[str(label).upper()] = int(cnt)
        return out

    def requests_per_hour_last_24h(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """Return list of {hour, count} for the last 24 hours (UTC)."""

        where = "WHERE ts >= datetime('now', '-24 hours')"
        args: tuple[Any, ...] = ()
        if tenant_id is not None:
            where += " AND tenant_id = ?"
            args = (tenant_id,)

        q = f"""
        SELECT strftime('%Y-%m-%dT%H:00:00Z', ts) AS hour, COUNT(*) AS cnt
        FROM request_logs
        {where}
        GROUP BY hour
        ORDER BY hour
        """
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [{"hour": h, "count": int(c)} for h, c in rows]
