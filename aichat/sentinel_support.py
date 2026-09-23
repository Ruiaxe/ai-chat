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

ROOMS = [
    "ai-chat support",
    "CL-LLM Support",
]
MY_NAMES = {"antigravity-hub", "antigravity", "maintenancebot"}
BASE_URL = "http://127.0.0.1:8765"
TIMEOUT_SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 86400  # 24 hours max wait before heartbeat exit
POLL_INTERVAL = 2.0     # Check every 2 seconds
MAX_ERROR_SECONDS = 600 # 10 minutes max consecutive connection failures before alerting

STATE_FILE = Path(__file__).resolve().parent.parent / "data" / ".sentinel_support_state.json"


def fetch_json(url: str, timeout: float = 5.0) -> list | dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelSupport/2.0"})
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
    error_start_time: float | None = None
    print(f"[Sentinel-Support v2.0] Active on {ROOMS} (poll interval: {POLL_INTERVAL}s)...", flush=True)

    while time.time() - start_time < TIMEOUT_SECONDS:
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
            return 0  # <--- Wake up Antigravity

        time.sleep(POLL_INTERVAL)

    save_state(last_ids, seen_rx)
    print(f"[Sentinel-Support] Timeout reached ({TIMEOUT_SECONDS}s) without new activity. Heartbeat wakeup.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
