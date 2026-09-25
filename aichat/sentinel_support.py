"""
Sentinel Support Watcher for Antigravity-Hub (v2.0).
Listens for new support requests and reactions across support channels.
Exits immediately (sys.exit(0)) when new external messages or reactions are detected,
triggering a reactive wake-up in Antigravity without polling loops or wasted tokens.

Enhancements:
- Persistent state file (.sentinel_support_state.json) so no messages are lost between runs.
- Wakes up on new reactions (e.g. human emoji feedback).
- Full multi-room sweep before waking up.
- Unreachable server detection with explicit alert.
- Output truncation for large messages (>4000 chars).
"""
import json
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request

import os

ROOMS = [
    "ai-chat support",
    "CL-LLM Support",
    "CL-Neural",
]
MY_NAMES = {"antigravity-hub", "antigravity", "maintenancebot", "sentinelsupport"}

def _get_base_url() -> str:
    env_url = os.environ.get("AICHAT_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")
    info_file = Path(__file__).resolve().parent.parent / ".server_info.json"
    if info_file.exists():
        try:
            data = json.loads(info_file.read_text(encoding="utf-8"))
            if data.get("base_url"):
                return data["base_url"].rstrip("/")
        except Exception:
            pass
    return "http://192.168.1.197:8765"

BASE_URL = _get_base_url()
SENTINEL_TOKEN = os.environ.get("SENTINEL_TOKEN", "530c8a7b16f49706682fc79da0c2b5fe")

def _get_timeout() -> int:
    for a in sys.argv[1:]:
        if a.isdigit():
            return int(a)
    return 86400

TIMEOUT_SECONDS = _get_timeout()  # Max wait before heartbeat exit in single-run mode
POLL_INTERVAL = 2.0     # Check every 2 seconds
MAX_ERROR_SECONDS = 600 # 10 minutes max consecutive connection failures before alerting

STATE_FILE = Path(__file__).resolve().parent.parent / "data" / ".sentinel_support_state.json"


def fetch_json(url: str, timeout: float = 5.0) -> list | dict | None:
    req = urllib.request.Request(url, headers={
        "User-Agent": "SentinelSupport/2.1",
        "X-Agent-Name": "SentinelSupport",
        "X-Member-Token": SENTINEL_TOKEN,
        "X-Agent-Token": SENTINEL_TOKEN,
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_latest_id(room_name: str) -> int:
    try:
        url = f"{BASE_URL}/api/rooms/{urllib.parse.quote(room_name)}/messages?limit=1"
        data = fetch_json(url)
        if data and isinstance(data, list):
            return data[-1]["id"]
    except Exception:
        pass
    return 0


def load_state() -> tuple[dict[str, int], dict[str, list[str]]]:
    """Loads last known message IDs and seen reactions per room."""
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            last_ids = data.get("last_ids", {})
            seen_rx = data.get("reactions", {})
            return last_ids, seen_rx
        except Exception:
            pass
    return {}, {}


def save_state(last_ids: dict[str, int], seen_rx: dict[str, list[str]]) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(
            json.dumps({"last_ids": last_ids, "reactions": seen_rx}, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception:
        pass


def main():
    is_daemon = "--daemon" in sys.argv or "--continuous" in sys.argv
    saved_ids, seen_rx = load_state()
    last_ids = {}
    is_initial_baseline = False

    for room in ROOMS:
        if room in saved_ids and saved_ids[room] > 0:
            last_ids[room] = saved_ids[room]
        else:
            last_ids[room] = get_latest_id(room)
            is_initial_baseline = True
        print(f"[Sentinel-Support] Initialized #{room} at last_id={last_ids[room]}", flush=True)

    start_time = time.time()
    last_heartbeat_time = time.time()
    error_start_time: float | None = None
    mode_str = "Continuous Daemon" if is_daemon else f"Single-run (timeout {TIMEOUT_SECONDS}s)"
    print(f"[Sentinel-Support v2.1] Mode: {mode_str} | Active on {ROOMS} (poll interval: {POLL_INTERVAL}s)...", flush=True)

    while is_daemon or (time.time() - start_time < TIMEOUT_SECONDS):
        detected_events = []
        connection_failed = False

        for room in ROOMS:
            curr_last = last_ids[room]
            # Inspect messages since (last_id - 30) to catch new reactions on recent messages
            fetch_since = max(0, curr_last - 30) if curr_last > 0 else 0
            url = f"{BASE_URL}/api/rooms/{urllib.parse.quote(room)}/messages?since_id={fetch_since}&limit=100"

            try:
                msgs = fetch_json(url)
                if not isinstance(msgs, list):
                    continue

                for m in msgs:
                    mid = m["id"]
                    sender = m.get("sender", "").strip()
                    sender_norm = sender.lower()

                    # 1. Check for new messages from external users/agents
                    if mid > curr_last:
                        last_ids[room] = max(last_ids[room], mid)
                        if sender_norm not in MY_NAMES:
                            content = m.get("content", "")
                            if len(content) > 4000:
                                content = content[:4000] + f"\n[... {len(content)} caracteres no total]"
                            detected_events.append(
                                f"📩 [NOVA MENSAGEM em #{room}] #{mid} de @{sender} ({m.get('role', 'agent')}):\n{content}"
                            )

                    # 2. Check for new reactions on messages
                    for rx in m.get("reactions") or []:
                        emoji = rx.get("emoji", "")
                        users = rx.get("users") or []
                        rx_key = f"{room}:{mid}:{emoji}"
                        previously_seen = set(seen_rx.get(rx_key, []))
                        current_users = set(users)
                        new_users = current_users - previously_seen - MY_NAMES

                        seen_rx[rx_key] = list(current_users)

                        if new_users and not is_initial_baseline:
                            users_str = ", ".join(sorted(new_users))
                            detected_events.append(
                                f"✨ [NOVA REAÇÃO em #{room}] {emoji} por {users_str} na mensagem #{mid} (de @{sender})"
                            )

            except Exception:
                connection_failed = True

        is_initial_baseline = False

        if connection_failed:
            if error_start_time is None:
                error_start_time = time.time()
            elif time.time() - error_start_time > MAX_ERROR_SECONDS:
                print(f"\n⚠️ [ALERTA SENTINEL] Servidor ai-chat inacessível há mais de {MAX_ERROR_SECONDS}s!", flush=True)
                save_state(last_ids, seen_rx)
                if not is_daemon:
                    return 0
        else:
            error_start_time = None

        if detected_events:
            print("\n" + "="*70, flush=True)
            print("🚨 [SENTINEL ALERT] Atividade detetada em canal de suporte:", flush=True)
            print("="*70, flush=True)
            print("\n\n".join(detected_events), flush=True)
            print("="*70 + "\n", flush=True)
            save_state(last_ids, seen_rx)
            return 0  # Trigger reactive wakeup in Antigravity assistant

        # Periodic heartbeat log in daemon mode (every 5 minutes)
        if is_daemon and (time.time() - last_heartbeat_time >= 300):
            last_heartbeat_time = time.time()
            print(f"[Sentinel-Support] Heartbeat OK: active on {ROOMS} (presence verified)", flush=True)

        time.sleep(POLL_INTERVAL)

    save_state(last_ids, seen_rx)
    print(f"[Sentinel-Support] Timeout reached ({TIMEOUT_SECONDS}s) without new activity. Heartbeat wakeup.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
