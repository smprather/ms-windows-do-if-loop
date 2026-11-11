"""watchglass status: combine status.json, offline markers and the config on disk."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from watchglass import transfer
from watchglass.config import Discovery
from watchglass.durations import format_duration
from watchglass.locks import probe_lock
from watchglass.offline import read_offline
from watchglass.paths import Paths


def service_running(paths: Paths) -> bool:
    if not paths.runtime.is_dir():
        return False
    with probe_lock(paths.service_lock) as held:
        return held


def read_status(paths: Paths) -> dict[str, Any] | None:
    try:
        data = json.loads(paths.status_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def orphaned_state(paths: Paths, discovery: Discovery) -> list[str]:
    root = paths.state_home / "watches"
    if not root.is_dir():
        return []
    return sorted(entry.name for entry in root.iterdir() if entry.is_dir() and entry.name not in discovery.watches)


def collect_status(paths: Paths, discovery: Discovery, names: list[str]) -> dict[str, Any]:
    running = service_running(paths)
    saved = (read_status(paths) or {}) if running else {}
    saved_watches = saved.get("watches", {})
    watches = {}
    for name in names or list(discovery.watches):
        entry: dict[str, Any] = dict(saved_watches.get(name) or {"known_to_service": False})
        marker = read_offline(paths, name)
        entry["offline"] = marker.to_dict() if marker else None
        entry["exists"] = name in discovery.watches
        watches[name] = entry
    service: dict[str, Any] = {"running": running}
    if running:
        saved_service = saved.get("service", {})
        service.update({key: saved_service.get(key) for key in ("pid", "version", "started", "updated", "config_error")})
    return {
        "service": service,
        "watches": watches,
        "invalid_watches": saved.get("invalid_watches", {}),
        "problems": [str(problem) for problem in discovery.problems],
        "orphaned_state": orphaned_state(paths, discovery),
    }


def _epoch(value: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return None


def _ago(value: Any, now: float) -> str:
    stamp = _epoch(value)
    return "?" if stamp is None else format_duration(max(int(now - stamp), 0))


def _until(value: Any, now: float) -> str:
    stamp = _epoch(value)
    return "?" if stamp is None else format_duration(max(int(stamp - now), 0))


def _failed_reason(last: dict[str, Any]) -> str:
    """The first failed hook's reason, else the poll's own reason, as text."""
    results = last.get("results")
    if isinstance(results, list):
        for result in results:
            if isinstance(result, dict) and result.get("status") not in ("ok", None):
                reason = result.get("reason")
                if isinstance(reason, str) and reason:
                    return reason
    reason = last.get("reason")
    return reason if isinstance(reason, str) else ""


def failure_kind(entry: dict[str, Any]) -> str | None:
    """A short classification of the last poll's failure, or None when it did not fail.

    A mid-transfer drop, an unreachable destination, a refused overwrite and a rejected credential call for
    different operator actions, so the label says which one happened instead of repeating the raw reason.
    """
    last = entry.get("last_poll")
    if not isinstance(last, dict) or not last.get("failed"):
        return None
    reason = _failed_reason(last).lower()
    offline = entry.get("offline")
    if isinstance(offline, dict) and offline.get("permanent"):
        return "auth rejected"
    if "authentication failed" in reason or "permission denied (publickey" in reason or "host key verification failed" in reason:
        return "auth rejected"
    if "refuses to overwrite" in reason or ("permission denied" in reason and ("dest open" in reason or "remote open" in reason)):
        return "refused overwrite"
    if "not reachable" in reason or "no ssh banner" in reason:
        return "unreachable"
    if any(word in reason for word in (
        "connection reset", "connection closed", "connection timed out", "broken pipe", "unexpected eof", "connection lost"
    )):
        return "dropped mid-transfer"
    if "timed out" in reason:
        return "timed out"
    return "failed"


def in_flight_text(in_flight: dict[str, Any], activity: dict[str, Any] | None, *, now: float) -> str:
    """What a watch is doing right now: the hook, for how long, and what it is transferring."""
    started = _epoch(in_flight.get("started_at"))
    running = "?" if started is None else format_duration(max(int(now - started), 0))
    text = f"{in_flight.get('target') or in_flight.get('hook')} running {running}"
    if isinstance(activity, dict):
        text += f" · {transfer.activity_text(activity)}"
    return text


def watch_state(entry: dict[str, Any], *, in_flight: bool = False) -> str:
    """The one state label for a watch entry, shared by `watchglass status` and the TUI.

    Precedence: offline (a marker), parked (enabled = false), transferring/polling, idle (the service does not
    know the watch), waiting (its last poll answered `unknown`, e.g. the destination is unreachable) and online.
    """
    if entry.get("offline"):
        return "offline"
    enabled = entry.get("enabled")
    if isinstance(enabled, bool) and not enabled:
        return "parked"
    if entry.get("in_flight") or in_flight:
        return "transferring" if isinstance(entry.get("transfer"), dict) else "polling"
    known = entry.get("known_to_service")
    if isinstance(known, bool) and not known:
        return "idle"
    last = entry.get("last_poll")
    if isinstance(last, dict) and last.get("outcome") == "unknown":
        return "waiting"
    return "online"


def _watch_line(name: str, entry: dict[str, Any], now: float) -> str:
    label = watch_state(entry)
    parts = [f"{name:<20} {label:<12}"]
    if "condition" in entry:
        parts.append(f"condition {'TRUE' if entry['condition'] else 'FALSE'}")
    if "failures" in entry:
        parts.append(f"failures {entry['failures']}")
    last = entry.get("last_poll")
    if last:
        parts.append(f"last {last['outcome']}{' FAILED' if last['failed'] else ''} {_ago(last['at'], now)} ago")
    if entry.get("next_poll"):
        parts.append(f"next in {_until(entry['next_poll'], now)}")
    return "  ".join(parts)


def format_status(document: dict[str, Any], now: float) -> list[str]:
    service = document["service"]
    if service["running"]:
        lines = [
            f"service: running (pid {service.get('pid')}, version {service.get('version')}, "
            f"status updated {_ago(service.get('updated'), now)} ago)"
        ]
        if service.get("config_error"):
            lines.append(f"    global config error (running the previous config): {service['config_error']}")
    else:
        lines = ["service: not running (start it with: watchglass run)"]
    for name, entry in document["watches"].items():
        lines.append(_watch_line(name, entry, now))
        if entry.get("in_flight"):
            lines.append(f"    {in_flight_text(entry['in_flight'], entry.get('transfer'), now=now)}")
            transfer_now = entry.get("transfer")
            path = transfer.activity_path(transfer_now) if isinstance(transfer_now, dict) else None
            if path:
                lines.append(f"      -> {path}")  # where the bytes are going (issue 31)
        last = entry.get("last_poll")
        if isinstance(last, dict) and last.get("outcome") == "unknown":
            reason = last.get("reason")
            if isinstance(reason, str) and reason:
                lines.append(f"    waiting: {reason}")
        failure = failure_kind(entry) if not entry.get("offline") else None
        if failure is not None:
            lines.append(f"    last failure: {failure}")
        offline = entry.get("offline")
        if offline:
            detail = f"    offline since {offline['since']}: {offline['reason']}"
            if offline.get("permanent"):
                detail += " (permanent: no trial polls)"
            lines.append(detail)
            if offline.get("last_failure"):
                lines.append(f"    last failure: {offline['last_failure']}")
        if entry.get("config_error"):
            lines.append(f"    config error (running the previous config): {entry['config_error'].splitlines()[0]}")
        if not entry.get("exists", True):
            lines.append("    the watch directory no longer exists")
    for name, error in document.get("invalid_watches", {}).items():
        lines.append(f"{name:<20} invalid  not started: {error.splitlines()[0]}")
    for problem in document.get("problems", []):
        lines.append(f"problem: {problem}")
    for name in document.get("orphaned_state", []):
        lines.append(f"orphaned state: {name} (state of a watch that no longer exists; to rename a watch use watchglass rename)")
    return lines
