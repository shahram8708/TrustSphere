"""Report cache that uses Redis when available with an in-memory fallback.

This ensures the web process and Celery workers share generated report state
when Redis is available (recommended). The API keeps the same functions
`get_report`, `set_report`, and `list_recent_reports` and returns
`created_at` as a `datetime` object for compatibility with templates.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

_redis_client = None
_in_memory_cache = {}


def _init_redis():
    try:
        import redis

        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        client = redis.Redis.from_url(url, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None


_redis_client = _init_redis()


def _iso_to_dt(val: Optional[str]):
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None


def get_report(task_id):
    """Return one cached report entry (or None)."""
    if _redis_client:
        key = f"trustsphere:report:{task_id}"
        raw = _redis_client.get(key)
        if not raw:
            return None
        entry = json.loads(raw)
        # normalize created_at to datetime for templates
        if entry.get("created_at"):
            entry["created_at"] = _iso_to_dt(entry.get("created_at"))
        return entry
    # fallback to in-memory
    entry = _in_memory_cache.get(task_id)
    return entry


def set_report(
    task_id,
    status,
    content=None,
    format_str=None,
    report_type=None,
    institution_id=None,
):
    """Create or update a cached report entry.

    When Redis is available the entry is stored as JSON under
    `trustsphere:report:<task_id>` and the task id is added to the
    sorted set `trustsphere:reports:recent` (score is creation epoch).
    """
    now = datetime.utcnow()
    if _redis_client:
        key = f"trustsphere:report:{task_id}"
        raw = _redis_client.get(key)
        entry = json.loads(raw) if raw else {}
        # preserve existing created_at when present
        created_at = _iso_to_dt(entry.get("created_at")) or now
        entry.update({"status": status, "created_at": created_at.isoformat()})
        if content is not None:
            entry["content"] = content
        elif "content" not in entry:
            entry["content"] = None
        if format_str is not None:
            entry["format"] = format_str
        if report_type is not None:
            entry["report_type"] = report_type
        if institution_id is not None:
            entry["institution_id"] = institution_id
        # store JSON and add to recent set
        _redis_client.set(key, json.dumps(entry))
        score = int(created_at.timestamp())
        _redis_client.zadd("trustsphere:reports:recent", {task_id: score})
        # set a reasonable TTL so stale reports expire (configurable)
        ttl = int(os.environ.get("REPORT_CACHE_TTL", 60 * 60 * 24))
        try:
            _redis_client.expire(key, ttl)
        except Exception:
            pass
        # return a copy with created_at as datetime for compatibility
        entry["created_at"] = created_at
        return entry

    # fallback to in-memory behavior
    entry = _in_memory_cache.get(task_id, {})
    entry.update({"status": status, "created_at": entry.get("created_at") or now})
    if content is not None:
        entry["content"] = content
    elif "content" not in entry:
        entry["content"] = None
    if format_str is not None:
        entry["format"] = format_str
    if report_type is not None:
        entry["report_type"] = report_type
    if institution_id is not None:
        entry["institution_id"] = institution_id
    _in_memory_cache[task_id] = entry
    return entry


def list_recent_reports(institution_id=None, limit=10):
    """Return recent reports sorted newest first.

    When using Redis this reads the `trustsphere:reports:recent` sorted set
    to return the most recent task ids, then fetches each report key.
    The returned `created_at` value is a `datetime` to match earlier
    in-memory behavior used by templates.
    """
    rows = []
    if _redis_client:
        ids = _redis_client.zrevrange("trustsphere:reports:recent", 0, limit - 1)
        for task_id in ids:
            raw = _redis_client.get(f"trustsphere:report:{task_id}")
            if not raw:
                continue
            entry = json.loads(raw)
            created_at = _iso_to_dt(entry.get("created_at")) or datetime.min
            entry["created_at"] = created_at
            if institution_id is not None and entry.get("institution_id") != institution_id:
                continue
            rows.append({**entry, "task_id": task_id})
        return rows[:limit]

    # fallback to in-memory
    for task_id, entry in _in_memory_cache.items():
        if institution_id is not None and entry.get("institution_id") != institution_id:
            continue
        rows.append({**entry, "task_id": task_id})
    rows.sort(key=lambda item: item.get("created_at") or datetime.min, reverse=True)
    return rows[:limit]
