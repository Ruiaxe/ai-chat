#!/usr/bin/env python3
"""
aichat-wait.py — Cliente Universal de Wake-up para ai-chat (v3.1)

Script cliente leve e autónomo, sem dependências externas (apenas biblioteca padrão Python).
Faz long-polling ao endpoint /api/wake do servidor ai-chat, gerindo a presença do agente
(transições de estado entre 'a escutar', 'a trabalhar' e 'sem trabalho') e entregando
novas mensagens/tarefas com confirmação fiável (ACK).

Segurança de Credenciais:
  - Tokens NUNCA são passados por argumento de linha de comandos (--token não existe).
  - O token é obtido da variável de ambiente AICHAT_AGENT_TOKEN ou de ficheiro de perfil
    (~/.aichat/<agente>.json ou ~/.aichat/config.json).
  - A saída do script nunca expõe o token completo.

Códigos de saída (Exit codes):
  0: Nova mensagem / tarefa recebida (ou sucesso no --selftest / --register)
  2: Erro de ligação / rede / servidor indisponível (5xx ou connection refused)
  3: Tempo limite (timeout) sem novo trabalho
  4: Erro de autenticação / não autorizado / agente desativado (401/403)
  1: Argumentos inválidos ou erro inesperado
"""

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONNECTION_ERROR = 2
EXIT_TIMEOUT_NO_WORK = 3
EXIT_AUTH_ERROR = 4


def mask_token(token: str) -> str:
    """Mascara o token para nunca ser exposto em logs ou saída."""
    if not token:
        return ""
    if len(token) > 12:
        return f"{token[:8]}...{token[-4:]}"
    return "[redacted]"


def get_aichat_dir() -> Path:
    """Devolve a pasta de perfis ~/.aichat."""
    try:
        p = Path.home() / ".aichat"
    except Exception:
        import tempfile
        p = Path(tempfile.gettempdir()) / ".aichat"
    return p


def resolve_credentials(agent_name: str = "", base_url: str = "") -> Tuple[str, str]:
    """
    Resolve o token e url a partir de:
    1. Variável de ambiente (AICHAT_AGENT_TOKEN, AICHAT_TOKEN, AI_CHAT_TOKEN)
    2. Perfil do agente (~/.aichat/<agent>.json)
    3. Perfil padrão (~/.aichat/config.json)
    Devolve (token, resolved_url).
    """
    env_token = (
        os.environ.get("AICHAT_AGENT_TOKEN")
        or os.environ.get("AICHAT_TOKEN")
        or os.environ.get("AI_CHAT_TOKEN")
        or ""
    ).strip()
    env_url = (
        os.environ.get("AICHAT_URL")
        or os.environ.get("AI_CHAT_URL")
        or ""
    ).strip()

    token = env_token
    resolved_url = base_url or env_url

    aichat_dir = get_aichat_dir()
    profiles_to_check: list[Path] = []
    if agent_name:
        profiles_to_check.append(aichat_dir / f"{agent_name}.json")
    profiles_to_check.append(aichat_dir / "config.json")

    for prof in profiles_to_check:
        if prof.exists():
            try:
                cfg = json.loads(prof.read_text(encoding="utf-8"))
                if not token:
                    token = (cfg.get("token") or cfg.get("agent_token") or "").strip()
                if not resolved_url and cfg.get("url"):
                    resolved_url = cfg.get("url").strip()
                if token:
                    break
            except Exception:
                pass

    if not resolved_url:
        resolved_url = "http://localhost:8000"

    return token, resolved_url


def get_last_batch_id(agent_name: str = "") -> str:
    """Lê o último lote guardado localmente para confirmação automática (ACK)."""
    aichat_dir = get_aichat_dir()
    candidates = []
    if agent_name:
        candidates.append(aichat_dir / f".last_batch_{agent_name}")
    candidates.append(aichat_dir / ".last_batch")

    for f in candidates:
        if f.exists():
            try:
                val = f.read_text(encoding="utf-8").strip()
                if val:
                    return val
            except Exception:
                pass
    return ""


def save_last_batch_id(batch_id: str, agent_name: str = "") -> None:
    """Guarda o lote recebido para confirmação automática na próxima chamada."""
    if not batch_id:
        return
    aichat_dir = get_aichat_dir()
    try:
        aichat_dir.mkdir(parents=True, exist_ok=True)
        target = aichat_dir / f".last_batch_{agent_name}" if agent_name else aichat_dir / ".last_batch"
        target.write_text(str(batch_id).strip(), encoding="utf-8")
        # Também manter .last_batch atualizado
        (aichat_dir / ".last_batch").write_text(str(batch_id).strip(), encoding="utf-8")
    except Exception:
        pass


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ai-chat Universal Wake-up Client (v3.1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Códigos de saída:
  0  Nova mensagem ou trabalho recebido (ou selftest / registo OK)
  2  Erro de ligação / servidor indisponível
  3  Tempo limite esgotado sem novo trabalho
  4  Token inválido, em falta ou agente desativado

Exemplos:
  # Executar como hook no Claude Code:
  python tools/aichat-wait.py --hook claude-code --room geral

  # Registar um novo agente contra o servidor:
  python tools/aichat-wait.py --register NovoAgente

  # Executar indicando o perfil do agente (~/.aichat/Builder.json):
  python tools/aichat-wait.py --agent Builder --timeout 120

  # Verificar conectividade e token:
  python tools/aichat-wait.py --selftest
""",
    )

    default_url = os.environ.get("AICHAT_URL") or os.environ.get("AI_CHAT_URL") or "http://localhost:8000"
    default_room = os.environ.get("AICHAT_ROOM") or os.environ.get("AI_CHAT_ROOM") or ""
    default_timeout = int(os.environ.get("AICHAT_TIMEOUT") or 300)

    parser.add_argument(
        "--url",
        default=default_url,
        help=f"URL base do servidor ai-chat (padrão: {default_url})",
    )
    parser.add_argument(
        "--agent",
        default="",
        help="Callsign do agente para carregar perfil (~/.aichat/<agente>.json)",
    )
    parser.add_argument(
        "--register",
        default="",
        metavar="CALLSIGN",
        help="Regista novo agente com callsign no servidor e grava perfil em ~/.aichat/<CALLSIGN>.json",
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
        default="",
        help="ID da mensagem/lote anteriormente processado para confirmação (padrão: automático via estado local)",
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
    query_str = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None and v != ""})
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


def make_post_request(
    base_url: str,
    path: str,
    body: Dict[str, Any],
    timeout_seconds: float = 30.0,
) -> tuple[int, Dict[str, Any]]:
    """Executa pedido HTTP POST com corpo JSON."""
    clean_url = base_url.rstrip("/")
    full_url = f"{clean_url}{path}"
    data_bytes = json.dumps(body).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "aichat-wait/3.1",
    }
    req = urllib.request.Request(full_url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status_code = resp.getcode()
            body_text = resp.read().decode("utf-8", errors="replace")
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


def run_register(callsign: str, base_url: str) -> int:
    """Regista um agente no servidor e grava o perfil local em ~/.aichat/<callsign>.json."""
    clean_callsign = callsign.strip()
    if not clean_callsign:
        print("[ERRO] Callsign não pode ser vazio.", file=sys.stderr)
        return EXIT_GENERAL_ERROR

    print(f"=== Registo de Agente: {clean_callsign} ===", file=sys.stderr)
    print(f"Servidor: {base_url}", file=sys.stderr)

    try:
        code, resp = make_post_request(base_url, "/api/register", {"callsign": clean_callsign})
    except ConnectionError as ce:
        print(f"[ERRO] {ce}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except Exception as e:
        print(f"[ERRO] Erro ao submeter registo: {e}", file=sys.stderr)
        return EXIT_GENERAL_ERROR

    if code in (200, 201):
        aichat_dir = get_aichat_dir()
        aichat_dir.mkdir(parents=True, exist_ok=True)
        prof_file = aichat_dir / f"{clean_callsign}.json"
        token = resp.get("token") or resp.get("agent_token") or ""
        profile_data = {
            "callsign": clean_callsign,
            "url": base_url,
            "token": token,
            "status": resp.get("status", "pending"),
        }
        prof_file.write_text(json.dumps(profile_data, indent=2, ensure_ascii=False), encoding="utf-8")
        status_msg = resp.get("message") or "Pedido de registo submetido. Aguarda aprovação em /admin."
        print(f"[OK] {status_msg}")
        print(f"Perfil guardado em: {prof_file}")
        if token:
            print(f"Token recebido: {mask_token(token)}")
        else:
            print("Token: pendente de emissão pelo administrador.")
        return EXIT_SUCCESS
    else:
        err = resp.get("error") or resp.get("message") or f"HTTP {code}"
        print(f"[ERRO] Falha no registo ({code}): {err}", file=sys.stderr)
        return EXIT_GENERAL_ERROR if code != 403 else EXIT_AUTH_ERROR


def run_selftest(args: argparse.Namespace, token: str, url: str) -> int:
    """Executa autoteste de conectividade, autenticação e permissões."""
    print("=== ai-chat Wake-up Client: Self-Test ===", file=sys.stderr)
    print(f"Servidor: {url}", file=sys.stderr)
    print(f"Sala alvo: {args.room or '(todas)'}", file=sys.stderr)

    if not token:
        print("[FAIL] Token do agente em falta. Defina AICHAT_AGENT_TOKEN ou configure ~/.aichat/<agente>.json.", file=sys.stderr)
        return EXIT_AUTH_ERROR

    token_preview = mask_token(token)
    print(f"Token: {token_preview}", file=sys.stderr)

    try:
        code, data = make_request(url, "/api/rooms", token, timeout_seconds=10.0)
    except ConnectionError as ce:
        print(f"[FAIL] Ligação falhou: {ce}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    if code == 401:
        print("[FAIL] Autenticação falhou: Token inválido ou revogado (HTTP 401).", file=sys.stderr)
        return EXIT_AUTH_ERROR
    if code == 403:
        print("[FAIL] Acesso negado: Agente desativado ou sem permissão (HTTP 403).", file=sys.stderr)
        return EXIT_AUTH_ERROR
    if code != 200:
        print(f"[FAIL] Servidor retornou código inesperado: HTTP {code}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    print("[PASS] Ligação e autenticação com sucesso.", file=sys.stderr)

    rooms = data.get("rooms", data) if isinstance(data, dict) else data
    if isinstance(rooms, list):
        room_names = [r.get("name") for r in rooms if isinstance(r, dict)]
        print(f"[INFO] Salas acessíveis ({len(room_names)}): {', '.join(room_names) or '(nenhuma)'}", file=sys.stderr)
        if args.room and args.room not in room_names:
            print(f"[WARN] A sala '{args.room}' não consta na lista de salas com acesso concedido.", file=sys.stderr)

    # Teste de leitura não bloqueante (timeout_seconds=0)
    try:
        w_code, w_data = make_request(
            url,
            "/api/wake",
            token,
            params={"timeout_seconds": 0, "room": args.room, "format": "json"},
            timeout_seconds=10.0,
        )
        if w_code == 200:
            status = w_data.get("status")
            print(f"[PASS] Endpoint /api/wake operacional (status='{status}').", file=sys.stderr)
        else:
            print(f"[WARN] Chamada de teste a /api/wake devolveu HTTP {w_code}.", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] Teste a /api/wake falhou: {e}", file=sys.stderr)

    print("=== Self-Test Concluído com Sucesso ===", file=sys.stderr)
    return EXIT_SUCCESS


def format_claude_code_hook(data: Dict[str, Any], default_room: str) -> str:
    """Formata mensagens para Claude Code Stop Hook (JSON block decision)."""
    messages = data.get("messages", [])
    if not messages:
        return json.dumps({
            "decision": "allow",
            "message": "Sem novas tarefas no ai-chat. A aguardar próximo ciclo.",
        }, ensure_ascii=False)

    lines = ["Nova atividade no ai-chat:"]
    role_reminder = data.get("role_reminder")
    if role_reminder:
        if isinstance(role_reminder, dict):
            disp = role_reminder.get("display_name") or role_reminder.get("role_key") or "Agente"
            rem = role_reminder.get("reminder_text", "")
            lines.append(f"[Lembrete de Papel] {disp}: {rem}")
        else:
            lines.append(f"[Lembrete de Papel] {role_reminder}")

    for m in messages:
        sender = m.get("sender") or m.get("sender_name") or "alguém"
        room = m.get("room_name") or m.get("room") or default_room or "geral"
        content = m.get("content", "").strip()
        lines.append(f"- [#{room}] @{sender}: {content}")

    lines.append("\nProcessa estas mensagens e responde no ai-chat.")
    reason_str = "\n".join(lines)

    return json.dumps({
        "decision": "block",
        "reason": reason_str,
    }, ensure_ascii=False, indent=2)


def format_opencode_hook(data: Dict[str, Any], default_room: str) -> str:
    """Formata mensagens para OpenCode hook."""
    messages = data.get("messages", [])
    if not messages:
        return ""

    lines = []
    for m in messages:
        sender = m.get("sender") or m.get("sender_name") or "alguém"
        room = m.get("room_name") or m.get("room") or default_room or "geral"
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
        room = m.get("room_name") or m.get("room") or default_room or "geral"
        content = m.get("content", "").strip()
        lines.append(f"  [#{room}] @{sender}: {content}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    # Subcomando de registo
    if args.register:
        return run_register(args.register, args.url)

    token, base_url = resolve_credentials(agent_name=args.agent, base_url=args.url)

    if args.selftest:
        return run_selftest(args, token, base_url)

    if not token:
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": "Aviso ai-chat: Token não configurado. Defina AICHAT_AGENT_TOKEN ou perfil em ~/.aichat/<agente>.json.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        print(
            "[ERRO] Token do agente em falta. Defina a variável AICHAT_AGENT_TOKEN ou utilize --agent <callsign> com perfil em ~/.aichat/<agente>.json.",
            file=sys.stderr,
        )
        return EXIT_AUTH_ERROR

    # Resolução de ACK: se não foi fornecido explicitamente na linha de comandos,
    # utiliza a confirmação automática do último lote guardado localmente
    effective_ack = args.ack
    if not effective_ack:
        effective_ack = get_last_batch_id(args.agent)

    params: Dict[str, Any] = {
        "timeout_seconds": max(0, args.timeout),
        "format": "json",
    }
    if effective_ack:
        params["ack"] = effective_ack
    if args.room:
        params["room"] = args.room

    # Timeout HTTP um pouco maior que o timeout de long-polling para permitir resposta do servidor
    http_timeout = max(30.0, float(args.timeout) + 30.0)

    if args.verbose:
        masked = mask_token(token)
        print(
            f"[DEBUG] A escutar {base_url}/api/wake (timeout={args.timeout}s, room={args.room or 'todas'}, ack={effective_ack or 'none'}, token={masked})",
            file=sys.stderr,
        )

    try:
        code, data = make_request(base_url, "/api/wake", token, params=params, timeout_seconds=http_timeout)
    except ConnectionError as ce:
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": f"Aviso ai-chat: Erro de rede ou servidor indisponível ({ce}). A aguardar próximo ciclo.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        print(f"[ERRO] {ce}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR
    except Exception as e:
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": f"Aviso ai-chat: Erro inesperado na ligação ({e}). A aguardar próximo ciclo.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        print(f"[ERRO] Erro inesperado na ligação: {e}", file=sys.stderr)
        return EXIT_GENERAL_ERROR

    if code in (401, 403):
        err = data.get("error", "Não autorizado ou agente desativado")
        print(f"[ERRO] Acesso negado ({code}): {err}", file=sys.stderr)
        return EXIT_AUTH_ERROR

    if code >= 500:
        err = data.get("error", f"Erro no servidor (HTTP {code})")
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": f"Aviso ai-chat: Servidor indisponível ({err}). A aguardar próximo ciclo.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        print(f"[ERRO] {err}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    if code != 200:
        err = data.get("error", f"Código HTTP inesperado: {code}")
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": f"Aviso ai-chat: Resposta inesperada ({err}). A aguardar próximo ciclo.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        print(f"[ERRO] {err}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    # Verificar resposta do servidor
    status = data.get("status")
    messages = data.get("messages", [])

    if status == "error":
        err_msg = data.get("error", "Erro retornado pelo servidor")
        err_lower = err_msg.lower()
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": f"Aviso ai-chat: Servidor reportou erro ({err_msg}). A aguardar próximo ciclo.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        if any(w in err_lower for w in ("autenticação", "acesso negado", "token", "desativado", "unauthorized", "forbidden")):
            print(f"[ERRO] Servidor devolveu erro: {err_msg}", file=sys.stderr)
            return EXIT_AUTH_ERROR
        print(f"[ERRO] Servidor devolveu erro: {err_msg}", file=sys.stderr)
        return EXIT_CONNECTION_ERROR

    # Se atingiu timeout sem novo trabalho
    if status in ("timeout", "no_work") or (not messages and status not in ("new_work", "new_messages")):
        if args.hook == "claude-code":
            print(
                json.dumps({
                    "decision": "allow",
                    "message": "Sem novas tarefas no ai-chat. A aguardar próximo ciclo.",
                }, ensure_ascii=False)
            )
            return EXIT_SUCCESS
        elif args.format == "json" and args.hook == "none":
            print(json.dumps(data, ensure_ascii=False, indent=2))
        elif args.verbose:
            print("Tempo limite esgotado sem novas mensagens.", file=sys.stderr)
        return EXIT_TIMEOUT_NO_WORK

    # Novo trabalho recebido! Guardar batch_id localmente para confirmação automática na chamada seguinte
    batch_id = data.get("batch_id")
    if batch_id:
        save_last_batch_id(str(batch_id), args.agent)

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
