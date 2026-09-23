"""
Sentinel Support Watcher for Antigravity-Hub.
Listens for new support requests across #ai-chat support and #CL-LLM Support.
Exits immediately when a new message from another user/agent is detected,
triggering a reactive wake-up in Antigravity.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

ROOMS = [
    "ai-chat support",
    "CL-LLM Support",
]
MY_NAME = "antigravity-hub"
BASE_URL = "http://127.0.0.1:8765"
TIMEOUT_SECONDS = 1800  # 30 minutes max wait before heartbeat exit
POLL_INTERVAL = 2.0     # Check every 2 seconds


def get_latest_id(room_name: str) -> int:
    try:
        url = f"{BASE_URL}/api/rooms/{urllib.parse.quote(room_name)}/messages?limit=1"
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelSupport/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data:
                return data[-1]["id"]
    except Exception:
        pass
    return 0


def check_for_new(room_name: str, since_id: int) -> list[dict]:
    url = f"{BASE_URL}/api/rooms/{urllib.parse.quote(room_name)}/messages?since_id={since_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelSupport/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        msgs = json.loads(resp.read().decode("utf-8"))
        # Filter out messages from Antigravity-Hub itself
        external = [
            m for m in msgs
            if m.get("sender", "").strip().lower() != MY_NAME
        ]
        return external


def main():
    last_ids = {}
    for room in ROOMS:
        curr = get_latest_id(room)
        last_ids[room] = curr
        print(f"[Sentinel-Support] Initialized #{room} at last_id={last_ids[room]}", flush=True)

    start_time = time.time()
    print(f"[Sentinel-Support] Active and listening on {ROOMS} (poll interval: {POLL_INTERVAL}s, timeout: {TIMEOUT_SECONDS}s)...", flush=True)

    while time.time() - start_time < TIMEOUT_SECONDS:
        for room in ROOMS:
            try:
                new_msgs = check_for_new(room, last_ids[room])
                if new_msgs:
                    print(f"\n🚨 [NEW_SUPPORT_REQUEST] Found {len(new_msgs)} new message(s) in #{room}:", flush=True)
                    for m in new_msgs:
                        print(f"  - Message #{m['id']} from @{m['sender']} ({m.get('role', 'agent')}):", flush=True)
                        print(f"    {m['content']}", flush=True)
                    return 0
            except Exception:
                pass
        time.sleep(POLL_INTERVAL)

    print(f"[Sentinel-Support] Timeout reached ({TIMEOUT_SECONDS}s) without new messages. Heartbeat wakeup.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
