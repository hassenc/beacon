#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import importlib.util


ROOT = pathlib.Path(__file__).resolve().parent.parent
MONITOR = ROOT / "scripts" / "beacon-monitor.py"
SPEC = importlib.util.spec_from_file_location("beacon_monitor", MONITOR)
MONITOR_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MONITOR_MODULE)


def run(fixture, state, extra_env=None, test=True):
    fixture_path = state.parent / "fixture.json"
    fixture_path.write_text(json.dumps(fixture))
    command = [sys.executable, str(MONITOR), "--fixture", str(fixture_path), "--state", str(state)]
    if test:
        command.append("--test")
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(command, capture_output=True, text=True, env=env)


with tempfile.TemporaryDirectory() as directory:
    base = pathlib.Path(directory)
    state = base / "state.json"
    healthy = {"health": True, "failed_notifications": 0, "pending_age_seconds": 0, "backup_age_seconds": 60, "disk_free_percent": 80}
    failed = {"health": False, "failed_notifications": 0, "pending_age_seconds": 0, "backup_age_seconds": 60, "disk_free_percent": 80}
    assert run(healthy, state).returncode == 0
    assert run(failed, state).returncode == 0
    assert run(failed, state).returncode == 0
    third = run(failed, state)
    assert third.returncode == 1 and third.stdout.count("ALERT ") == 1
    repeated = run(failed, state)
    assert "ALERT " not in repeated.stdout
    recovered = run(healthy, state)
    assert recovered.returncode == 0 and "\"event\": \"recovery\"" in recovered.stdout

    overlap_state = base / "overlap-state.json"
    assert run(healthy, overlap_state).returncode == 0
    assert run(failed, overlap_state).returncode == 0
    assert run(failed, overlap_state).returncode == 0
    assert run(failed, overlap_state).returncode == 1
    disk_failed = dict(failed, disk_free_percent=5)
    overlap = run(disk_failed, overlap_state)
    assert overlap.returncode == 1 and '"disk": "free_percent=5.0"' in overlap.stdout and overlap.stdout.count("ALERT ") == 1
    assert run(disk_failed, overlap_state).stdout.count("ALERT ") == 0
    assert run(healthy, overlap_state).returncode == 0

    missing_destination_state = base / "missing-destination-state.json"
    missing_destination_env = {"BEACON_ALERT_URL": ""}
    assert run(healthy, missing_destination_state, missing_destination_env, test=False).returncode == 0
    assert run(failed, missing_destination_state, missing_destination_env, test=False).returncode == 0
    assert run(failed, missing_destination_state, missing_destination_env, test=False).returncode == 0
    assert run(failed, missing_destination_state, missing_destination_env, test=False).returncode == 2

    orphan_dir = base / "backups"
    orphan_dir.mkdir()
    orphan_metadata = orphan_dir / "beacon-orphan.json"
    orphan_metadata.write_text(json.dumps({"format": "beacon-production-backup-v1", "artifact": "beacon-orphan.backup", "copy_complete": True, "created_at": "2099-01-01T00:00:00Z", "sha256": "x", "bytes": 1, "destination_sha256": "x", "destination_bytes": 1}))
    assert MONITOR_MODULE.latest_backup_age(orphan_dir) is None

    receiver = base / "receiver.py"
    received = base / "received.log"
    receiver.write_text(
        "import http.server, pathlib, sys\n"
        "class Handler(http.server.BaseHTTPRequestHandler):\n"
        "  def do_POST(self):\n"
        "    pathlib.Path(sys.argv[2]).open('a').write(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode()+'\\n')\n"
        "    self.send_response(204); self.end_headers()\n"
        "  def log_message(self, *args): pass\n"
        "server=http.server.HTTPServer(('127.0.0.1',0), Handler)\n"
        "pathlib.Path(sys.argv[1]).write_text(str(server.server_port))\n"
        "server.serve_forever()\n"
    )
    port_file = base / "port"
    receiver_process = subprocess.Popen([sys.executable, str(receiver), str(port_file), str(received)])
    try:
        for _ in range(100):
            if port_file.exists():
                break
            time.sleep(0.01)
        webhook_env = {"BEACON_ALERT_URL": "http://127.0.0.1:" + port_file.read_text() + "/alert"}
        delivery_state = base / "delivery-state.json"
        assert run(healthy, delivery_state, webhook_env, test=False).returncode == 0
        assert run(failed, delivery_state, webhook_env, test=False).returncode == 0
        assert run(failed, delivery_state, webhook_env, test=False).returncode == 0
        assert run(failed, delivery_state, webhook_env, test=False).returncode == 1
        assert run(failed, delivery_state, webhook_env, test=False).returncode == 1
        assert run(healthy, delivery_state, webhook_env, test=False).returncode == 0
        messages = received.read_text().splitlines()
        assert len(messages) == 2
        assert '"event": "alert"' in messages[0]
        assert '"event": "recovery"' in messages[1]

        retry_state = base / "retry-state.json"
        retry_env = {"BEACON_ALERT_URL": "http://127.0.0.1:1/unreachable"}
        assert run(healthy, retry_state, retry_env, test=False).returncode == 0
        assert run(failed, retry_state, retry_env, test=False).returncode == 0
        assert run(failed, retry_state, retry_env, test=False).returncode == 0
        assert run(failed, retry_state, retry_env, test=False).returncode == 2
        assert run(failed, retry_state, webhook_env, test=False).returncode == 1
    finally:
        receiver_process.terminate()
        receiver_process.wait(timeout=5)
print("monitor fixtures: PASS")
