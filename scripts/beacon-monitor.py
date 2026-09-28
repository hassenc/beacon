#!/usr/bin/env python3
"""Small, dependency-free Beacon health/operations monitor.

The monitor reads no case content. It emits sanitized JSON alerts to a
configured webhook, or to stdout in --test mode. State is kept locally so
transient failures do not page immediately and repeated alerts are suppressed.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def load_config(path):
    if not path:
        return
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


def setting(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"missing {name}")
    return value


def number(name, default):
    try:
        return float(setting(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"invalid {name}") from exc


def iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_health(url):
    request = urllib.request.Request(url, headers={"User-Agent": "beacon-monitor/1"})
    try:
        with urllib.request.urlopen(request, timeout=number("BEACON_MONITOR_TIMEOUT_SECONDS", 8)) as response:
            response.read(128)
            return 200 <= response.status < 300, f"http_{response.status}"
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return False, type(exc).__name__


def latest_backup_age(backup_dir):
    newest = None
    for path in pathlib.Path(backup_dir).glob("beacon-*.json"):
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
            if metadata.get("format") != "beacon-production-backup-v1" or metadata.get("copy_complete") is not True:
                continue
            artifact = metadata["artifact"]
            backup_path = path.parent / artifact
            if backup_path.name != path.with_suffix(".backup").name or not backup_path.is_file():
                continue
            if int(metadata["bytes"]) != backup_path.stat().st_size or int(metadata["destination_bytes"]) != backup_path.stat().st_size:
                continue
            digest = hashlib.sha256()
            with backup_path.open("rb") as backup_file:
                for chunk in iter(lambda: backup_file.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != metadata["sha256"] or digest.hexdigest() != metadata["destination_sha256"]:
                continue
            created = datetime.fromisoformat(metadata["created_at"].replace("Z", "+00:00"))
            if newest is None or created > newest:
                newest = created
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
            continue
    if newest is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - newest).total_seconds())


def database_state():
    dsn = setting("BEACON_MONITOR_DATABASE_URL")
    dsn_file = setting("BEACON_MONITOR_DATABASE_URL_FILE")
    if not dsn and dsn_file:
        dsn = pathlib.Path(dsn_file).read_text(encoding="utf-8").strip()
    if not dsn:
        return None, "database_not_configured"
    query = (
        "SELECT count(*) FILTER (WHERE state='FAILED'), "
        "COALESCE(EXTRACT(EPOCH FROM (now()-min(created) "
        "FILTER (WHERE state='PENDING'))),0)::bigint FROM notifications"
    )
    try:
        result = subprocess.run(
            ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", dsn, "-c", query],
            check=True,
            capture_output=True,
            text=True,
            timeout=number("BEACON_MONITOR_TIMEOUT_SECONDS", 8),
        ).stdout.strip()
        failed, pending_age = result.split("|", 1)
        return {"failed_notifications": int(failed), "pending_age_seconds": int(pending_age)}, "ok"
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return None, type(exc).__name__


def live_snapshot():
    health_url = setting("BEACON_MONITOR_HEALTH_URL", required=True)
    healthy, health_detail = fetch_health(health_url)
    backup_dir = setting("BEACON_MONITOR_BACKUP_DIR", required=True)
    disk_path = setting("BEACON_MONITOR_DISK_PATH", backup_dir)
    usage = shutil.disk_usage(disk_path)
    db, db_detail = database_state()
    snapshot = {
        "health": healthy,
        "health_detail": health_detail,
        "backup_age_seconds": latest_backup_age(backup_dir),
        "disk_free_percent": (usage.free / usage.total) * 100 if usage.total else 0,
        "database_detail": db_detail,
    }
    if db:
        snapshot.update(db)
    return snapshot


def conditions(snapshot, state):
    failures = int(state.get("health_failures", 0))
    if snapshot.get("health"):
        failures = 0
    else:
        failures += 1
    state["health_failures"] = failures
    result = {}
    if failures >= int(number("BEACON_HEALTH_FAILURES", 3)):
        result["health"] = f"failed_for_{failures}_checks"
    if snapshot.get("failed_notifications", 0) > 0:
        result["failed_notifications"] = f"count={snapshot['failed_notifications']}"
    pending_age = snapshot.get("pending_age_seconds")
    if pending_age is not None and pending_age > number("BEACON_PENDING_AGE_SECONDS", 900):
        result["pending_notifications"] = f"age_seconds={pending_age:.0f}"
    backup_age = snapshot.get("backup_age_seconds")
    if backup_age is None:
        result["backup"] = "no_verified_backup_metadata"
    elif backup_age > number("BEACON_BACKUP_AGE_SECONDS", 93600):
        result["backup"] = f"age_seconds={backup_age:.0f}"
    if snapshot.get("disk_free_percent", 0) < number("BEACON_DISK_FREE_PERCENT", 20):
        result["disk"] = f"free_percent={snapshot['disk_free_percent']:.1f}"
    if snapshot.get("database_detail") not in (None, "ok"):
        result["database"] = snapshot["database_detail"]
    return result


def deliver(event, raised, resolved, active, snapshot, test_mode):
    payload = {
        "event": event,
        "source": "beacon-monitor",
        "at": iso_now(),
        "raised": raised,
        "resolved": resolved,
        "conditions": active,
    }
    if event == "alert":
        payload["checks"] = {k: v for k, v in snapshot.items() if k not in ("database_url",)}
    if test_mode:
        print("ALERT " + json.dumps(payload, sort_keys=True))
        return
    if not setting("BEACON_ALERT_URL"):
        raise RuntimeError("BEACON_ALERT_URL is required unless --test is used")
    token_file = setting("BEACON_ALERT_TOKEN_FILE")
    headers = {"Content-Type": "application/json", "User-Agent": "beacon-monitor/1"}
    if token_file:
        headers["Authorization"] = "Bearer " + pathlib.Path(token_file).read_text(encoding="utf-8").strip()
    request = urllib.request.Request(setting("BEACON_ALERT_URL"), json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=number("BEACON_MONITOR_TIMEOUT_SECONDS", 8)) as response:
        response.read(128)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="dotenv-style monitor configuration")
    parser.add_argument("--fixture", help="JSON snapshot for deterministic tests")
    parser.add_argument("--state", help="state file; defaults to BEACON_MONITOR_STATE_FILE")
    parser.add_argument("--test", action="store_true", help="print alerts instead of sending them")
    args = parser.parse_args()
    load_config(args.config or os.environ.get("BEACON_MONITOR_CONFIG_FILE"))
    state_path = pathlib.Path(args.state or setting("BEACON_MONITOR_STATE_FILE", "/var/lib/beacon/monitor-state.json"))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        snapshot = json.loads(pathlib.Path(args.fixture).read_text(encoding="utf-8")) if args.fixture else live_snapshot()
        active = conditions(snapshot, state)
        previous = state.get("active", {})
        if not isinstance(previous, dict):
            previous = {}
        raised = {key: value for key, value in active.items() if key not in previous}
        resolved = {key: value for key, value in previous.items() if key not in active}
        if raised or resolved:
            deliver("alert" if raised else "recovery", raised, resolved, active, snapshot, args.test)
        state["active"] = active
        state["last_run"] = iso_now()
        state_path.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "alert" if active else "ok", "conditions": active, "snapshot": snapshot}, sort_keys=True))
        return 1 if active else 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        print(f"MONITOR_ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
