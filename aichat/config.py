import json
import os
import socket
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
STATIC_DIR = Path(__file__).resolve().parent / "static"
SERVER_INFO_FILE = BASE_DIR / ".server_info.json"

# Ensure essential directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)


def find_free_port(start_port: int = 8765, max_attempts: int = 100) -> int:
    """Finds an available TCP port starting from start_port."""
    env_port = os.getenv("AICHAT_PORT")
    if env_port:
        try:
            return int(env_port)
        except ValueError:
            pass

    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue

    # Fallback to OS assigned free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def save_server_info(host: str, port: int) -> dict:
    """Saves server runtime details to .server_info.json for client discovery."""
    info = {
        "host": host,
        "port": port,
        "base_url": f"http://{host}:{port}",
        "web_url": f"http://{host}:{port}/",
        "sse_url": f"http://{host}:{port}/sse",
        "ws_url": f"ws://{host}:{port}/ws",
        "pid": os.getpid(),
    }
    try:
        with open(SERVER_INFO_FILE, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
    except Exception:
        pass
    return info


def get_server_info() -> dict | None:
    """Reads server runtime details if file exists."""
    if SERVER_INFO_FILE.exists():
        try:
            with open(SERVER_INFO_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None
