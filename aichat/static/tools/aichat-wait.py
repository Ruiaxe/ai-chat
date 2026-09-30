#!/usr/bin/env python3
"""
aichat-wait.py — Cliente Universal de Wake-up para ai-chat (v3.1)

Script cliente leve e autónomo, sem dependências externas (apenas biblioteca padrão Python).
Faz long-polling ao endpoint /api/wake do servidor ai-chat, gerindo a presença do agente
(transições de estado entre 'a escutar', 'a trabalhar' e 'sem trabalho') e entregando
novas mensagens/tarefas com confirmação fiável (ACK).

Códigos de saída (Exit codes):
  0: Nova mensagem / tarefa recebida (ou sucesso no --selftest)
  2: Erro de ligação / rede / servidor indisponível (5xx ou connection refused)
  3: Tempo limite (timeout) sem novo trabalho
  4: Erro de autenticação / não autorizado / agente desativado (401/403)
  1: Argumentos inválidos ou erro inesperado
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONNECTION_ERROR = 2
EXIT_TIMEOUT_NO_WORK = 3
EXIT_AUTH_ERROR = 4


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ai-chat Universal Wake-up Client (v3.1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Códigos de saída:
  0  Nova mensagem ou trabalho recebido (ou selftest OK)
  2  Erro de ligação / servidor indisponível
  3  Tempo limite esgotado sem novo trabalho
  4  Token inválido ou agente desativado

Exemplos:
  # Executar como hook no Claude Code:
  python tools/aichat-wait.py --hook claude-code --room geral

  # Executar com formato JSON para automação:
  python tools/aichat-wait.py --format json --timeout 120

  # Verificar conectividade e token:
  python tools/aichat-wait.py --selftest
""",
    )

    default_url = os.environ.get("AICHAT_URL") or os.environ.get("AI_CHAT_URL") or "http://localhost:8000"
    default_token = (
        os.environ.get("AICHAT_AGENT_TOKEN")
        or os.environ.get("AICHAT_TOKEN")
        or os.environ.get("AI_CHAT_TOKEN")
        or ""
    )
    default_room = os.environ.get("AICHAT_ROOM") or os.environ.get("AI_CHAT_ROOM") or ""
    default_timeout = int(os.environ.get("AICHAT_TIMEOUT") or 300)

    parser.add_argument(
        "--url",
        default=default_url,
        help=f"URL base do servidor ai-chat (padrão: {default_url})",
    )
    parser.add_argument(
        "--token",
        default=default_token,
        help="Token de autenticação do agente (ou variável AICHAT_AGENT_TOKEN)",
    )
    parser.add_argument(
        "--room",
        default=default_room,
        help="Nome da sala a escutar (padrão: todas as salas atribuídas)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=default_timeout,
        help=f"Tempo limite em segundos para long-polling (padrão: {default_timeout}s)",
    )
    parser.add_argument(
        "--ack",
        type=int,
        default=0,
        help="ID da mensagem/lote anteriormente processado para confirmação (padrão: 0)",
    )
    parser.add_argument(
        "--hook",
        choices=["none", "claude-code", "opencode"],
        default="none",
        help="Formato de saída otimizado para o harness especificado (none, claude-code, opencode)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Formato dos dados devolvidos em modo padrão (text ou json)",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Testa ligação, autenticação e permissões sem esperar por novo trabalho",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mostra informação detalhada de depuração em stderr",
    )

    return parser.parse_args(argv)


def make_request(
    base_url: str,
    path: str,
    token: str,
    params: Optional[Dict[str, Any]] = None,
    timeout_seconds: float = 650.0,
) -> tuple[int, Dict[str, Any]]:
    """
    Executa pedido HTTP GET com Bearer token e parâmetros opcionais.
    Devolve (status_code, response_dict).
    """
    clean_url = base_url.rstrip("/")
    query_str = urllib.parse.urlencode(params or {})
    full_url = f"{clean_url}{path}"
    if query_str:
        full_url = f"{full_url}?{query_str}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "aichat-wait/3.1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(full_url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status_code = resp.getcode()
            body_bytes = resp.read()
            body_text = body_bytes.decode("utf-8", errors="replace")
            try:
                data = json.loads(body_text)
            except Exception:
                data = {"raw": body_text}
            return status_code, data
    except urllib.error.HTTPError as he:
        status_code = he.code
        body_text = he.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(body_text)
        except Exception:
            data = {"error": body_text or he.reason}
        return status_code, data
    except urllib.error.URLError as ue:
        raise ConnectionError(f"Falha ao ligar ao servidor {base_url}: {ue.reason}") from ue
    except OSError as oe:
        raise ConnectionError(f"Erro de socket/rede: {oe}") from oe


def run_selftest(args: argparse.Namespace) -> int:
    """Executa autoteste de conectividade, autenticação e permissões."""
    print("=== ai-chat Wake-up Client: Self-Test ===", file=sys.stderr)
    print(f"Servidor: {args.url}", file=sys.stderr)
    print(f"Sala alvo: {args.room or '(todas)'}", file=sys.stderr)

    if not args.token:
        print("[FAIL] Token do agente em falta. Forneça --token ou defina AICHAT_AGENT_TOKEN.", file=sys.stderr)
        return EXIT_AUTH_ERROR

    token_preview = args.token[:6] + "..." if len(args.token) > 8 else "***"
    print(f"Token configurado: {token_preview}", file=sys.stderr)

    # 1. Testar endpoint /api/wake com timeout 0 (verificação imediata)
    try:
        params: Dict[str, Any] = {"timeout_seconds": 0, "ack": 0, "format": "json"}
        if args.room:
            params["room"] = args.room

        code, data = make_request(args.url, "/api/wake", args.token, params=params, timeout_seconds=15.0)

        if code in (401, 403):
            err_msg = data.get("error", "Credenciais rejeitadas")
            print(f"[FAIL] Autenticação rejeitada (HTTP {code}): {err_msg}", file=sys.stderr)
            return EXIT_AUTH_ERROR

        if code >= 400:
            err_msg = data.get("error", f"HTTP {code}")
            print(f"[FAIL] Erro HTTP {code}: {err_msg}", file=sys.stderr)
            return EXIT_CONNECTION_ERROR

        print(f"[OK] Ligação ao servidor bem sucedida (HTTP {code})", file=sys.stderr)
        print(f"[OK] Token de agente válido e autenticado", file=sys.stderr)
        status_received = data.get("status", "unknown")
        print(f"[OK] Endpoint /api/wake operacional (status='{status_received}')", file=sys.stderr)

        # 2. Se sala especificada, testar team-status
        if args.room:
            ts_code, ts_data = make_request(
                args.url,
                f"/api/rooms/{urllib.parse.quote(args.room)}/team-status",
                args.token,
                timeout_seconds=15.0,
            )
            if ts_code == 200 and ts_data.get("status") == "success":
                print(f"[OK] Acesso confirmado à sala #{args.room}", file=sys.stderr)
            elif ts_code in (401, 403):
                print(f"[WARN] Sem permissão para consultar sala #{args.room} (HTTP {ts_code})", file=sys.stderr)
            else:
                print(f"[INFO] team-status para #{args.room}: HTTP {ts_code}", file=sys.stderr)

        print("[OK] Todos os testes passaram com sucesso!", file=sys.stderr)
        return EXIT_SUCCESS

    except ConnectionError as ce:
        print(f"[FAIL] Erro de ligação: {ce}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except Exception as e:
        print(f"[FAIL] Erro inesperado: {e}", file=sys.stderr)
        return EXIT_GENERAL_ERROR


def format_claude_code_hook(data: Dict[str, Any], default_room: str) -> str:
    """Formata mensagens para injeção limpa no Claude Code."""
    messages = data.get("messages", [])
    if not messages:
        return ""

    lines = []
    lines.append(f"Nova atividade no ai-chat ({len(messages)} mensagem{'s' if len(messages) > 1 else ''}):")
    lines.append("")
    for m in messages:
        sender = m.get("sender") or m.get("sender_name") or "alguém"
        room = m.get("room") or default_room or "geral"
        content = m.get("content", "").strip()
        lines.append(f"[#{room}] @{sender}:")
        lines.append(content)
        lines.append("")

    return "\n".join(lines).strip()


def format_opencode_hook(data: Dict[str, Any], default_room: str) -> str:
    """Formata mensagens para OpenCode hook."""
    messages = data.get("messages", [])
    if not messages:
        return ""

    lines = []
    for m in messages:
        sender = m.get("sender") or m.get("sender_name") or "alguém"
        room = m.get("room") or default_room or "geral"
        content = m.get("content", "").strip()
        lines.append(f"[ai-chat:opencode] #{room} @{sender}: {content}")
    return "\n".join(lines)


def format_text_output(data: Dict[str, Any], default_room: str) -> str:
    """Formata mensagens em texto legível para humanos ou agentes em consola."""
    messages = data.get("messages", [])
    if not messages:
        return "Sem novas mensagens."

    is_redelivered = data.get("redelivered", False)
    header = f"[ai-chat] Recebidas {len(messages)} mensagem(ns)"
    if is_redelivered:
        header += " (reentrega de lote não confirmado)"
    header += ":"

    lines = [header]
    for m in messages:
        sender = m.get("sender") or m.get("sender_name") or "alguém"
        room = m.get("room") or default_room or "geral"
        content = m.get("content", "").strip()
        lines.append(f"  [#{room}] @{sender}: {content}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.selftest:
        return run_selftest(args)

    if not args.token:
        print(
            "[ERRO] Token do agente em falta. Forneça --token ou defina a variável AICHAT_AGENT_TOKEN.",
            file=sys.stderr,
        )
        return EXIT_AUTH_ERROR

    params: Dict[str, Any] = {
        "timeout_seconds": max(0, args.timeout),
        "ack": args.ack,
        "format": "json",
    }
    if args.room:
        params["room"] = args.room

    # Timeout HTTP um pouco maior que o timeout de long-polling para permitir resposta do servidor
    http_timeout = max(30.0, float(args.timeout) + 30.0)

    if args.verbose:
        print(
            f"[DEBUG] A escutar {args.url}/api/wake (timeout={args.timeout}s, room={args.room or 'todas'}, ack={args.ack})",
            file=sys.stderr,
        )

    try:
        code, data = make_request(args.url, "/api/wake", args.token, params=params, timeout_seconds=http_timeout)
    except ConnectionError as ce:
        print(f"[ERRO] {ce}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except Exception as e:
        print(f"[ERRO] Erro inesperado na ligação: {e}", file=sys.stderr)
        return EXIT_GENERAL_ERROR

    if code in (401, 403):
        err = data.get("error", "Não autorizado ou agente desativado")
        print(f"[ERRO] Acesso negado ({code}): {err}", file=sys.stderr)
        return EXIT_AUTH_ERROR

    if code >= 500:
        err = data.get("error", f"Erro no servidor (HTTP {code})")
        print(f"[ERRO] {err}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    if code != 200:
        err = data.get("error", f"Código HTTP inesperado: {code}")
        print(f"[ERRO] {err}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    # Verificar resposta do servidor
    status = data.get("status")
    messages = data.get("messages", [])

    if status == "error":
        err_msg = data.get("error", "Erro retornado pelo servidor")
        print(f"[ERRO] Servidor devolveu erro: {err_msg}", file=sys.stderr)
        err_lower = err_msg.lower()
        if any(w in err_lower for w in ("autenticação", "acesso negado", "token", "desativado", "unauthorized", "forbidden")):
            return EXIT_AUTH_ERROR
        return EXIT_CONNECTION_ERROR

    # Se atingiu timeout sem novo trabalho
    if status in ("timeout", "no_work") or (not messages and status not in ("new_work", "new_messages")):
        if args.format == "json" and args.hook == "none":
            print(json.dumps(data, ensure_ascii=False, indent=2))
        elif args.verbose:
            print("Tempo limite esgotado sem novas mensagens.", file=sys.stderr)
        return EXIT_TIMEOUT_NO_WORK

    # Novo trabalho recebido!
    if args.hook == "claude-code":
        out = format_claude_code_hook(data, args.room)
        if out:
            print(out)
    elif args.hook == "opencode":
        out = format_opencode_hook(data, args.room)
        if out:
            print(out)
    else:
        if args.format == "json":
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            print(format_text_output(data, args.room))

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
