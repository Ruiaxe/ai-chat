#!/usr/bin/env python
"""
Launcher script for AI Chat Room MCP Server.

Starts the FastAPI/Starlette web server + MCP SSE endpoint + WebSockets.
"""
import argparse
import os
import socket
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
from aichat.mcp_server import hub, mcp
from aichat.web_app import create_app


def print_banner(host: str, port: int, one_time_code: str = "") -> None:
    display_host = host
    if host in ("0.0.0.0", "::"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            display_host = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                display_host = socket.gethostbyname(socket.gethostname())
            except Exception:
                display_host = "localhost"

    web_url = f"http://{display_host}:{port}/"
    login_url = f"http://{display_host}:{port}/?auth={one_time_code}" if one_time_code else web_url
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
 🔑 One-Time Login URL:    {login_url}
 🔑 One-Time Code:         {one_time_code}
 🔐 Master Human Token:    {hub.human_token} (saved in data/.human_token)
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
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1 - loopback only)")
    parser.add_argument("--port", type=int, default=None, help="Port to bind (default: automatic free port starting at 8765)")
    parser.add_argument("--allow-remote", action="store_true", help="Allow binding to non-loopback host (WARNING: exposes chat to network)")
    parser.add_argument("--allowed-hosts", nargs="*", default=None, help="Explicit allowed hostnames/IPs for Host header validation when remote is allowed")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the web browser")
    args = parser.parse_args()

    host = args.host
    is_loopback = host in ("127.0.0.1", "localhost", "::1")
    if not is_loopback and not args.allow_remote:
        print(f"\n❌ ERRO DE SEGURANÇA: Recusa de ligação à interface '{host}'.")
        print("O ai-chat restringe-se a loopback (127.0.0.1) por omissão para evitar expor as salas à rede local.")
        print("Se pretende mesmo expor a todas as máquinas da rede, utilize a flag explícita: --allow-remote\n")
        sys.exit(1)

    if args.allow_remote and not is_loopback:
        print("\n⚠️  AVISO DE SEGURANÇA: A flag --allow-remote está ativa! As salas e API estão expostas à sua rede local.\n")

    port = args.port if args.port is not None else find_free_port(start_port=8765)

    # Save runtime info for external tools/scripts
    save_server_info(host=host, port=port)

    # Generate an ephemeral single-use login code for browser launch (D5)
    one_time_code = hub.generate_one_time_auth_code(expiry_seconds=600)

    # Print startup banner
    print_banner(host=host, port=port, one_time_code=one_time_code)

    if not args.no_browser:
        open_browser_delayed(f"http://{host}:{port}/?auth={one_time_code}")

    if args.allow_remote and not is_loopback:
        if args.allowed_hosts:
            allowed_hosts = list(args.allowed_hosts) + ["127.0.0.1", "localhost"]
        elif host != "0.0.0.0":
            allowed_hosts = [host, "127.0.0.1", "localhost"]
        else:
            print("⚠️  Aviso: Ao utilizar --host 0.0.0.0 sem --allowed-hosts, a validação de Host é desativada (*). Recomenda-se especificar os hostnames permitidos com --allowed-hosts.\n")
            allowed_hosts = ["*"]

        # Sync allowed hosts to FastMCP transport security
        if "*" in allowed_hosts:
            mcp.settings.transport_security.enable_dns_rebinding_protection = False
        else:
            for h in allowed_hosts:
                clean_h = h.split(":")[0]
                if clean_h not in mcp.settings.transport_security.allowed_hosts:
                    mcp.settings.transport_security.allowed_hosts.extend([clean_h, f"{clean_h}:*"])
    else:
        allowed_hosts = None

    app = create_app(allowed_hosts=allowed_hosts)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",  # Keep console clean so our chat messages stand out
        timeout_keep_alive=600,
    )


if __name__ == "__main__":
    main()
