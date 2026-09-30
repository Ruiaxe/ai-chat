"""
ai-chat v3 Command-Line Interface (CLI).
Provides administrative commands on the server / Raspberry Pi:
- Create initial and subsequent admin accounts (interactive password prompt, no defaults).
- Register agents and issue secure API tokens (aic_...).
- Rotate and revoke agent tokens.
- Manage room access permissions and roles.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from aichat.config import DATA_DIR
from aichat.crypto import hash_password
from aichat.storage_v3 import StorageV3, DEFAULT_V3_DB


def _get_storage(db_arg: str | None, require_exists: bool = True) -> StorageV3:
    if db_arg:
        p = Path(db_arg).resolve()
    else:
        # Check env var or default to chat_v3.db, fallback to chat.db if v3
        env_db = os.environ.get("AICHAT_DB_PATH")
        if env_db:
            p = Path(env_db).resolve()
        elif DEFAULT_V3_DB.exists():
            p = DEFAULT_V3_DB
        elif (DATA_DIR / "chat.db").exists():
            p = DATA_DIR / "chat.db"
        else:
            p = DEFAULT_V3_DB

    if require_exists and (not p.exists() or p.stat().st_size == 0):
        print(f"Erro: A base de dados não existe em '{p}'. Este comando exige uma base de dados existente.", file=sys.stderr)
        sys.exit(1)

    return StorageV3(p)


def cmd_create_admin(args: argparse.Namespace) -> int:
    st = _get_storage(args.db, require_exists=False)
    username = args.username.strip()
    if not username:
        print("Erro: O nome de utilizador (--username) não pode estar vazio.", file=sys.stderr)
        return 1

    existing = st.get_principal_by_name(username)
    if existing:
        print(f"Erro: O principal '{username}' já existe.", file=sys.stderr)
        return 1

    def _prompt_pwd(prompt: str) -> str:
        if not sys.stdin.isatty():
            return sys.stdin.readline().rstrip("\r\n")
        return getpass.getpass(prompt)

    pwd1 = _prompt_pwd(f"Palavra-passe para o admin '{username}': ")
    if not pwd1 or len(pwd1) < 8:
        print("Erro: A palavra-passe deve conter pelo menos 8 caracteres.", file=sys.stderr)
        return 1
    pwd2 = _prompt_pwd("Confirme a palavra-passe: ")
    if pwd1 != pwd2:
        print("Erro: As palavras-passe não coincidem.", file=sys.stderr)
        return 1
    pwd = pwd1

    pid = st.create_human(
        username=username,
        password=pwd,
        display_name=args.display_name or username,
        access_role="admin",
        must_change_password=0,
    )
    st.log_audit(
        actor_id=pid,
        actor_name=username,
        action="create_admin",
        target_type="principal",
        target_id=pid,
        details=f"Admin {username} criado via CLI",
    )
    print(f"Sucesso: Administrador '{username}' (ID: {pid}) criado com sucesso na BD {st.db_path.name}.")
    return 0


def cmd_create_agent(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    name = args.name.strip()
    if not name:
        print("Erro: O callsign do agente (--name) não pode estar vazio.", file=sys.stderr)
        return 1

    existing = st.get_principal_by_name(name)
    if existing:
        print(f"Erro: O principal '{name}' já existe.", file=sys.stderr)
        return 1

    role_id = None
    if args.role:
        r = st.get_role_by_key(args.role)
        if not r:
            print(f"Erro: O papel '{args.role}' não foi encontrado no catálogo.", file=sys.stderr)
            return 1
        role_id = r["id"]

    pid, raw_token = st.create_agent(
        callsign=name,
        display_name=args.display_name or name,
        default_role_id=role_id,
        is_system=1 if args.is_system else 0,
    )
    st.log_audit(
        actor_id=None,
        actor_name="cli",
        action="create_agent",
        target_type="principal",
        target_id=pid,
        details=f"Agente {name} criado via CLI (role: {args.role or 'nenhum'})",
    )

    print("\n" + "=" * 65)
    print(f" Agente '{name}' (ID: {pid}) registado com sucesso.")
    print("=" * 65)
    print(" Token de Acesso API (guarda agora em local seguro):")
    print(f"   {raw_token}")
    print(" ATENÇÃO: Por segurança, o token não voltará a ser exibido.")
    print("=" * 65 + "\n")
    return 0


def cmd_rotate_token(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    name = args.agent.strip()
    p = st.get_principal_by_name(name)
    if not p or p["kind"] != "agent":
        print(f"Erro: Agente '{name}' não encontrado.", file=sys.stderr)
        return 1

    revoke_old = not args.keep_old
    new_token, hint = st.rotate_agent_token(p["id"], revoke_old=revoke_old)
    st.log_audit(
        actor_id=None,
        actor_name="cli",
        action="rotate_token",
        target_type="credential",
        target_id=p["id"],
        details=f"Token rodado para {name} (novo hint: ...{hint}, revogar_anteriores={revoke_old})",
    )

    print("\n" + "=" * 65)
    print(f" Novo token emitido para o agente '{name}' (Hint: ...{hint}).")
    if revoke_old:
        print(" Os tokens anteriores foram revogados.")
    else:
        print(" Os tokens anteriores continuam ativos temporariamente.")
    print("=" * 65)
    print(" Novo Token de Acesso:")
    print(f"   {new_token}")
    print(" ATENÇÃO: Guarda o token agora. Não voltará a ser mostrado.")
    print("=" * 65 + "\n")
    return 0


def cmd_revoke_token(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    agent_name = args.agent.strip()
    hint = args.hint.strip()

    p = st.get_principal_by_name(agent_name)
    if not p or p["kind"] != "agent":
        print(f"Erro: Agente '{agent_name}' não encontrado.", file=sys.stderr)
        return 1

    ok = st.revoke_credential_by_hint(p["id"], hint)
    if ok:
        st.log_audit(
            actor_id=None,
            actor_name="cli",
            action="revoke_token",
            target_type="credential",
            target_id=p["id"],
            details=f"Token com hint ...{hint} revogado para agente {agent_name}",
        )
        print(f"Sucesso: Token com hint '...{hint}' revogado para o agente '{agent_name}'.")
        return 0
    else:
        print(f"Aviso: Nenhuma credencial ativa encontrada com o hint '...{hint}' para o agente '{agent_name}'.", file=sys.stderr)
        return 1


def cmd_list_principals(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    principals = st.list_principals(kind=args.kind)
    if not principals:
        print("Nenhum principal encontrado.")
        return 0

    print(f"{'ID':<4} {'Tipo':<7} {'Nome':<18} {'Nome Visível':<20} {'Papel/Nível':<16} {'Estado':<10}")
    print("-" * 80)
    for p in principals:
        role_desc = p.get("access_role") or "agent"
        print(f"{p['id']:<4} {p['kind']:<7} {p['name']:<18} {p['display_name']:<20} {role_desc:<16} {p['status']:<10}")
    return 0


def cmd_grant_room(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    room_name = args.room.strip()
    p_name = args.principal.strip()

    room = st.get_room_by_name(room_name)
    if not room:
        print(f"Erro: Sala '{room_name}' não encontrada.", file=sys.stderr)
        return 1

    p = st.get_principal_by_name(p_name)
    if not p:
        print(f"Erro: Principal '{p_name}' não encontrado.", file=sys.stderr)
        return 1

    role_id = None
    if args.role:
        r = st.get_role_by_key(args.role)
        if not r:
            print(f"Erro: Papel '{args.role}' não encontrado.", file=sys.stderr)
            return 1
        role_id = r["id"]

    can_write = 0 if args.read_only else 1
    st.grant_room_access(
        room_id=room["id"],
        principal_id=p["id"],
        role_id=role_id,
        can_write=can_write,
    )
    st.log_audit(
        actor_id=None,
        actor_name="cli",
        action="grant_room",
        target_type="room_access",
        target_id=room["id"],
        room_id=room["id"],
        details=f"Acesso concedido a {p_name} na sala {room_name} (role: {args.role or 'nenhum'}, can_write={can_write})",
    )
    mode = "leitura e escrita" if can_write else "apenas leitura"
    print(f"Sucesso: Acesso à sala '{room_name}' concedido a '{p_name}' ({mode}).")
    return 0


def cmd_revoke_room(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    room_name = args.room.strip()
    p_name = args.principal.strip()

    room = st.get_room_by_name(room_name)
    if not room:
        print(f"Erro: Sala '{room_name}' não encontrada.", file=sys.stderr)
        return 1

    p = st.get_principal_by_name(p_name)
    if not p:
        print(f"Erro: Principal '{p_name}' não encontrado.", file=sys.stderr)
        return 1

    ok = st.revoke_room_access(room["id"], p["id"])
    if ok:
        st.log_audit(
            actor_id=None,
            actor_name="cli",
            action="revoke_room",
            target_type="room_access",
            target_id=room["id"],
            room_id=room["id"],
            details=f"Acesso revogado para {p_name} na sala {room_name}",
        )
        print(f"Sucesso: Acesso de '{p_name}' à sala '{room_name}' revogado.")
        return 0
    else:
        print(f"Aviso: '{p_name}' não tinha acesso direto registado à sala '{room_name}'.")
        return 1


def cmd_reset_password(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    username = args.username.strip()
    if not username:
        print("Erro: O nome de utilizador (--username) não pode estar vazio.", file=sys.stderr)
        return 1

    p = st.get_principal_by_name(username)
    if not p or p.get("kind") != "human":
        print(f"Erro: Utilizador humano '{username}' não encontrado.", file=sys.stderr)
        return 1

    if args.password:
        pwd = args.password
    else:
        def _prompt_pwd(prompt: str) -> str:
            if not sys.stdin.isatty():
                return sys.stdin.readline().rstrip("\r\n")
            return getpass.getpass(prompt)

        pwd1 = _prompt_pwd(f"Nova palavra-passe para o utilizador '{username}': ")
        if not pwd1 or len(pwd1) < 8:
            print("Erro: A palavra-passe deve conter pelo menos 8 caracteres.", file=sys.stderr)
            return 1
        pwd2 = _prompt_pwd("Confirme a nova palavra-passe: ")
        if pwd1 != pwd2:
            print("Erro: As palavras-passe não coincidem.", file=sys.stderr)
            return 1
        pwd = pwd1

    new_hash = hash_password(pwd)
    must_change = 1 if args.must_change else 0
    conn = st._get_connection()
    with conn:
        conn.execute(
            """
            UPDATE humans
            SET password_hash = ?, failed_logins = 0, locked_until = NULL, must_change_password = ?
            WHERE principal_id = ?;
            """,
            (new_hash, must_change, p["id"]),
        )

    st.log_audit(
        actor_id=None,
        actor_name="cli",
        action="reset_password",
        target_type="principal",
        target_id=p["id"],
        details=f"Palavra-passe redefinida via CLI para {username} (must_change={bool(args.must_change)})",
    )
    change_note = " (alteração obrigatória no próximo login)" if must_change else ""
    print(f"Sucesso: Palavra-passe de '{username}' redefinida com sucesso. Bloqueio por tentativas falhadas limpo{change_note}.")
    return 0


def cmd_list_rooms(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    rooms = st.list_rooms(include_archived=True)
    if not rooms:
        print("Nenhuma sala encontrada.")
        return 0

    if not args.all:
        rooms = [r for r in rooms if not r.get("is_archived")]

    print(f"{'ID':<4} {'Nome':<22} {'Estado':<10} {'Membros':<8} {'Mensagens':<10} {'Tópico'}")
    print("-" * 80)
    for r in rooms:
        status_str = "arquivada" if r.get("is_archived") else "ativa"
        members = r.get("member_count", 0)
        messages = r.get("message_count", 0)
        topic = (r.get("topic") or "")[:35]
        print(f"{r['id']:<4} {r['name']:<22} {status_str:<10} {members:<8} {messages:<10} {topic}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    st = _get_storage(args.db)
    from aichat.storage import check_schema_version

    p = st.db_path
    size_bytes = p.stat().st_size
    size_str = f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024 * 1024 else f"{size_bytes / (1024 * 1024):.2f} MB"
    schema_v = check_schema_version(p)

    conn = st._get_connection()
    # Humans
    h_admins = conn.execute("SELECT COUNT(*) FROM humans WHERE access_role = 'admin';").fetchone()[0]
    h_users = conn.execute("SELECT COUNT(*) FROM humans WHERE access_role = 'user';").fetchone()[0]
    h_locked = conn.execute("SELECT COUNT(*) FROM humans WHERE locked_until IS NOT NULL AND locked_until > datetime('now');").fetchone()[0]

    # Agents
    a_active = conn.execute("SELECT COUNT(*) FROM principals p JOIN agents a ON p.id = a.principal_id WHERE p.status = 'active';").fetchone()[0]
    a_inactive = conn.execute("SELECT COUNT(*) FROM principals p JOIN agents a ON p.id = a.principal_id WHERE p.status = 'inactive';").fetchone()[0]
    a_pending = conn.execute("SELECT COUNT(*) FROM principals p JOIN agents a ON p.id = a.principal_id WHERE p.status = 'pending';").fetchone()[0]
    a_system = conn.execute("SELECT COUNT(*) FROM principals p JOIN agents a ON p.id = a.principal_id WHERE p.is_system = 1;").fetchone()[0]

    # Rooms
    r_active = conn.execute("SELECT COUNT(*) FROM rooms WHERE is_archived = 0;").fetchone()[0]
    r_archived = conn.execute("SELECT COUNT(*) FROM rooms WHERE is_archived = 1;").fetchone()[0]

    # Messages
    m_count = conn.execute("SELECT COUNT(*) FROM messages;").fetchone()[0]

    # Tasks
    t_count = conn.execute("SELECT COUNT(*) FROM tasks;").fetchone()[0]

    # Audit log
    audit_count = conn.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0]

    print("\n" + "=" * 65)
    print(" ESTADO DO SISTEMA & BASE DE DADOS (ai-chat v3)")
    print("=" * 65)
    print(f" Ficheiro SQLite:      {p}")
    print(f" Tamanho do ficheiro:  {size_str}")
    print(f" Versão do esquema:    v{schema_v or '?'}")
    print("-" * 65)
    print(f" Utilizadores Humanos: {h_admins + h_users} (Admins: {h_admins}, Normais: {h_users}, Bloqueados: {h_locked})")
    print(f" Agentes Registados:   {a_active + a_inactive + a_pending} (Ativos: {a_active}, Inativos: {a_inactive}, Pendentes: {a_pending}, Sistema: {a_system})")
    print(f" Salas:                {r_active + r_archived} (Ativas: {r_active}, Arquivadas: {r_archived})")
    print(f" Mensagens Totais:     {m_count}")
    print(f" Tarefas Totais:       {t_count}")
    print(f" Registos Auditoria:   {audit_count}")
    print("=" * 65 + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aichat.cli",
        description="ai-chat v3 administrative CLI.",
    )
    parser.add_argument("--db", default=None, help="Caminho personalizado para o ficheiro de base de dados SQLite.")
    subparsers = parser.add_subparsers(dest="subcommand", help="Comando a executar")

    # create-admin
    p_admin = subparsers.add_parser("create-admin", help="Criar um utilizador administrador humano.")
    p_admin.add_argument("--username", "-u", required=True, help="Nome de utilizador do administrador.")
    p_admin.add_argument("--display-name", "-d", default=None, help="Nome visível do administrador.")
    p_admin.set_defaults(func=cmd_create_admin)

    # reset-password
    p_reset_pwd = subparsers.add_parser("reset-password", help="Redefinir a palavra-passe de um utilizador humano.")
    p_reset_pwd.add_argument("--username", "-u", required=True, help="Nome de utilizador a redefinir.")
    p_reset_pwd.add_argument("--must-change", action="store_true", help="Forçar alteração de palavra-passe no primeiro login.")
    p_reset_pwd.add_argument("--password", "-p", default=None, help="Nova palavra-passe (se omitida, solicita de forma interativa sem eco).")
    p_reset_pwd.set_defaults(func=cmd_reset_password)

    # create-agent
    p_agent = subparsers.add_parser("create-agent", help="Registar um novo agente e gerar o seu token de API.")
    p_agent.add_argument("--name", "-n", required=True, help="Callsign único do agente.")
    p_agent.add_argument("--display-name", "-d", default=None, help="Nome visível do agente.")
    p_agent.add_argument("--role", "-r", default=None, help="Papel por defeito do agente (ex: developer, qa, devops).")
    p_agent.add_argument("--is-system", action="store_true", help="Marcar agente como serviço de sistema.")
    p_agent.set_defaults(func=cmd_create_agent)

    # rotate-token
    p_rot = subparsers.add_parser("rotate-token", help="Emitir um novo token de API para um agente.")
    p_rot.add_argument("--agent", "-a", required=True, help="Callsign do agente.")
    p_rot.add_argument("--keep-old", action="store_true", help="Manter tokens anteriores ativos (janela de rotação suave).")
    p_rot.set_defaults(func=cmd_rotate_token)

    # revoke-token
    p_rev = subparsers.add_parser("revoke-token", help="Revogar uma credencial específica de um agente.")
    p_rev.add_argument("--agent", "-a", required=True, help="Callsign do agente.")
    p_rev.add_argument("--hint", required=True, help="Últimos 4 carateres do token a revogar.")
    p_rev.set_defaults(func=cmd_revoke_token)

    # list-principals
    p_list = subparsers.add_parser("list-principals", help="Listar utilizadores e agentes registados.")
    p_list.add_argument("--kind", "-k", choices=["human", "agent"], default=None, help="Filtrar por tipo.")
    p_list.set_defaults(func=cmd_list_principals)

    # list-rooms
    p_rooms = subparsers.add_parser("list-rooms", help="Listar salas da base de dados com contagens.")
    p_rooms.add_argument("--all", "-a", action="store_true", help="Incluir salas arquivadas.")
    p_rooms.set_defaults(func=cmd_list_rooms)

    # status
    p_status = subparsers.add_parser("status", help="Consultar estado da base de dados, esquema e contagens.")
    p_status.set_defaults(func=cmd_status)

    # grant-room
    p_grant = subparsers.add_parser("grant-room", help="Conceder acesso de uma sala a um humano ou agente.")
    p_grant.add_argument("--room", required=True, help="Nome da sala.")
    p_grant.add_argument("--principal", required=True, help="Nome do utilizador ou agente.")
    p_grant.add_argument("--role", default=None, help="Papel atribuído nesta sala específica (ex: developer, qa).")
    p_grant.add_argument("--read-only", action="store_true", help="Acesso restrito a leitura (can_write=0).")
    p_grant.set_defaults(func=cmd_grant_room)

    # revoke-room
    p_unaccess = subparsers.add_parser("revoke-room", help="Revogar o acesso de um principal a uma sala.")
    p_unaccess.add_argument("--room", required=True, help="Nome da sala.")
    p_unaccess.add_argument("--principal", required=True, help="Nome do utilizador ou agente.")
    p_unaccess.set_defaults(func=cmd_revoke_room)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
