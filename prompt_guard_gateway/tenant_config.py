"""Multi-tenant configuration loading.

Each tenant has a JSON file at:
  config/tenants/{tenant_id}.json

If X-Tenant-ID header is missing or unknown, we fall back to:
  config/tenants/default.json
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import re


_TENANT_DIR = Path("config") / "tenants"


@dataclass(frozen=True)
class TenantConfig:
    tenant_id: str
    strict_mode: bool = True
    injection_threshold: float = 0.98
    jailbreak_threshold: float = 0.90
    rate_limit: int = 100
    # Action for SUSPICIOUS prompts: "warn" or "sanitize".
    suspicious_action: str = "warn"
    whitelist: list[str] | None = None
    # Precompiled whitelist regexes (cached at load time for low latency).
    whitelist_patterns: list[re.Pattern] | None = None
    hard_block: dict[str, Any] | None = None


_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, TenantConfig] = {}


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Tenant config must be a JSON object: {path}")
    return data


def load_tenant_config(tenant_id: str | None) -> TenantConfig:
    """Load tenant config from disk (cached in-process)."""

    tid = (tenant_id or "").strip() or "default"

    with _CACHE_LOCK:
        if tid in _CACHE:
            return _CACHE[tid]

    tenant_path = _TENANT_DIR / f"{tid}.json"
    if not tenant_path.exists():
        tid = "default"
        tenant_path = _TENANT_DIR / "default.json"

    data = _load_json(tenant_path)

    whitelist = list(data.get("whitelist") or [])
    compiled = [re.compile(re.escape(str(p).strip()), re.I) for p in whitelist if str(p).strip()]

    cfg = TenantConfig(
        tenant_id=str(data.get("tenant_id") or tid),
        strict_mode=bool(data.get("strict_mode", True)),
        injection_threshold=float(data.get("injection_threshold", 0.98)),
        jailbreak_threshold=float(data.get("jailbreak_threshold", 0.90)),
        rate_limit=int(data.get("rate_limit", 100)),
        suspicious_action=str(data.get("suspicious_action", "warn")),
        whitelist=whitelist,
        whitelist_patterns=compiled,
        hard_block=dict(data.get("hard_block") or {}),
    )

    with _CACHE_LOCK:
        _CACHE[cfg.tenant_id] = cfg
        # Also cache under the requested key if different.
        _CACHE.setdefault((tenant_id or "default").strip() or "default", cfg)
    return cfg


def tenant_rate_limit_string(cfg: TenantConfig) -> str:
    """Return a slowapi rate-limit string like "100/minute"."""
    per_min = max(1, int(cfg.rate_limit))
    return f"{per_min}/minute"
