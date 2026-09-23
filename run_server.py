#!/usr/bin/env python
"""
Launcher script for AI Chat Room MCP Server.

Starts the FastAPI/Starlette web server + MCP SSE endpoint + WebSockets.
"""
import argparse
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Add root directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn

from aichat.config import (
    BASE_DIR,
    DATA_DIR,
    LOGS_DIR,
    find_free_port,
    save_server_info,
)
from aichat.mcp_server import hub
from aichat.web_app import create_app


def print_banner(host: str, port: int) -> None:
    web_url = f"http://{host}:{port}/"
    auth_url = f"http://{host}:{port}/?auth={hub.human_token}"
    sse_url = f"http://{host}:{port}/sse"
    ws_url = f"ws://{host}:{port}/ws/<room>"
    db_path = DATA_DIR / "chat.db"
    python_exe = sys.executable
    bridge_path = BASE_DIR / "bridge_stdio.py"

    banner = f"""
================================================================================
🚀 AI CHAT ROOM - MCP SERVER & WEB HUB
================================================================================
 🌐 Web Interface:         {web_url}
 🔑 Human Web Login:        {auth_url}
 🔐 Human Token:            {hub.human_token}
 ⚡ MCP SSE Endpoint:      {sse_url}
 🔌 WebSocket Endpoint:    {ws_url}
 💾 SQLite Database:       {db_path}
 📁 Logs Directory:        {LOGS_DIR}
================================================================================
💡 QUICK SETUP FOR YOUR AGENTS:

 Option 1: MCP over HTTP (SSE) - Recommended for Cursor, Antigravity, Cline:
   URL: {sse_url}

 Option 2: MCP via stdio (Claude Desktop):
   Command: {python_exe}
   Args:    ["{bridge_path}"]

 Live chat activity will be displayed in real time below:
================================================================================
"""
    print(banner)


def open_browser_delayed(url: str, delay: float = 1.0) -> None:
    def _open():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    t = threading.Thread(target=_open, daemon=True)
    t.start()


def main():
    parser = argparse.ArgumentParser(description="Run AI Chat Room MCP Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Port to bind (default: automatic free port starting at 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the web browser")
    args = parser.parse_args()

    port = args.port if args.port is not None else find_free_port(start_port=8765)
    host = args.host

    # Save runtime info for external tools/scripts
    save_server_info(host=host, port=port)

    # Print startup banner
    print_banner(host=host, port=port)

    if not args.no_browser:
        open_browser_delayed(f"http://{host}:{port}/?auth={hub.human_token}")

    app = create_app()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",  # Keep console clean so our chat messages stand out
        timeout_keep_alive=600,
    )


if __name__ == "__main__":
    main()
