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
    get_git_commit,
)
from aichat.storage import check_schema_version, ChatStorage, resolve_db_target, get_db_origin
from aichat.mcp_server import hub, mcp
from aichat.web_app import create_app


def print_banner(host: str, port: int, one_time_code: str = "", db_path: Path | None = None, db_origin: str = "") -> None:
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
    actual_db = (db_path or hub.storage.db_path).resolve()
    schema_v = check_schema_version(actual_db)
    commit_hash = get_git_commit()
    expected_db = (DATA_DIR / "chat_v3.db").resolve()
    is_unexpected = actual_db != expected_db
    proxy_status = "Ativo (--trust-proxy)" if os.environ.get("AICHAT_TRUST_PROXY") == "1" else "Inativo (ignora X-Forwarded-For)"
    db_origin_display = db_origin or get_db_origin(actual_db)

    banner = f"""
================================================================================
🚀 AI CHAT ROOM - MCP SERVER & WEB HUB (v3.1 - commit {commit_hash})
================================================================================
 🌐 Web Interface:         {web_url}
 🔑 One-Time Login URL:    {login_url}
 🔑 One-Time Code:         {one_time_code}
 🔐 Master Human Token:    {hub.human_token} (saved in data/.human_token)
 ⚡ MCP SSE Endpoint:      {sse_url}
 🔌 WebSocket Endpoint:    {ws_url}
 💾 SQLite Database:       {actual_db} (esquema v{schema_v or '?'})
 📌 Origem da BD:          {db_origin_display}
 📁 Logs Directory:        {LOGS_DIR}
 🛡️  Trust Proxy:           {proxy_status}
================================================================================
"""
    if is_unexpected:
        banner += f"""⚠️  AVISO DE BASE DE DADOS:
   A base de dados em uso ({actual_db})
   NÃO É a base de dados de produção padrão ({expected_db})!
================================================================================
"""
    banner += f"""💡 CONFIGURAÇÃO RÁPIDA DE AGENTES:

 Claude Code:
   claude mcp add --transport sse aichat {sse_url} -H "Authorization: Bearer <token>" -s user

 Antigravity (mcpServers):
   "aichat": {{ "url": "{sse_url}", "headers": {{ "Authorization": "Bearer <token>" }} }}

 OpenCode (opencode.json):
   "aichat": {{ "type": "remote", "url": "{sse_url}", "enabled": true, "headers": {{ "Authorization": "Bearer <token>" }} }}

 aichat-wait (background / hook):
   curl -o aichat-wait.py {web_url}tools/aichat-wait.py
   ~/.aichat/<agente>.json: {{"url": "{web_url.rstrip('/')}", "token": "<token>"}}
   python aichat-wait.py --agent <agente>

 Mais opções e snippets prontos a copiar em: {web_url}admin (separador Agentes)
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
    parser.add_argument("--db", default=None, help="Caminho para o ficheiro da base de dados SQLite (omissão: data/chat_v3.db)")
    parser.add_argument("--init-db", action="store_true", help="Permite inicializar e criar uma nova base de dados se o ficheiro não existir")
    parser.add_argument("--allow-remote", action="store_true", help="Allow binding to non-loopback host (WARNING: exposes chat to network)")
    parser.add_argument("--allowed-hosts", nargs="*", default=None, help="Explicit allowed hostnames/IPs for Host header validation when remote is allowed")
    parser.add_argument("--trust-proxy", action="store_true", help="Trust X-Forwarded-For header for client IP (use only behind a trusted reverse proxy)")
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

    # Protect against running server with AICHAT_TESTING=1 active
    if os.environ.get("AICHAT_TESTING") == "1":
        print("\n❌ ERRO DE CONFIGURAÇÃO: A variável de ambiente AICHAT_TESTING=1 está ativa.", file=sys.stderr)
        print("O run_server.py recusa arrancar em modo de teste para evitar poluição ou riscos aos dados.", file=sys.stderr)
        print("Desative a variável AICHAT_TESTING antes de iniciar o servidor.\n", file=sys.stderr)
        sys.exit(1)

    if args.trust_proxy:
        os.environ["AICHAT_TRUST_PROXY"] = "1"

    # Validate database path before attempting to open or create
    db_target, db_origin = resolve_db_target(args.db)

    if not db_target.exists() and not args.init_db:
        print(f"\n❌ ERRO: A base de dados não existe em '{db_target}'.", file=sys.stderr)
        print("O run_server.py recusa criar uma base de dados nova em silêncio.", file=sys.stderr)
        print("Se pretende inicializar uma nova base de dados intencionalmente, use a flag: --init-db\n", file=sys.stderr)
        sys.exit(1)

    os.environ["AICHAT_ALLOW_DEFAULT_DB"] = "1"
    os.environ["AICHAT_DB_PATH"] = str(db_target)
    os.environ["AICHAT_DB_ORIGIN"] = db_origin
    hub.storage = ChatStorage(db_path=db_target)

    port = args.port if args.port is not None else find_free_port(start_port=8765)

    # Save runtime info for external tools/scripts
    save_server_info(host=host, port=port)

    # Generate an ephemeral single-use login code for browser launch (D5)
    one_time_code = hub.generate_one_time_auth_code(expiry_seconds=600)

    # Print startup banner
    print_banner(host=host, port=port, one_time_code=one_time_code, db_path=db_target, db_origin=db_origin)

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
        timeout_keep_alive=5,
        timeout_graceful_shutdown=2,
    )


if __name__ == "__main__":
    main()
