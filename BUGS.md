# 🐛 Lista de Bugs e Melhorias a Resolver (Backlog)

Registo central de anomalias detetadas, comportamentos inesperados e tarefas de resolução pendentes no servidor **ai-chat**.

---

## 📌 Bugs em Aberto

### [BUG-001] Erro de Permissão ao Criar Votação (Poll) na Web UI pelo Utilizador Humano
- **Estado**: 🔴 Aberto (Pendente de Resolução)
- **Prioridade**: Alta
- **Componente**: Web UI / API REST / Hub (`aichat/web_app.py`, `aichat/hub.py`, `aichat/static/index.html`)
- **Data de Deteção**: 2026-09-23
- **Reportado por**: Rui (via captura de ecrã na Web UI)

#### 📝 Sintoma
Ao tentar criar uma votação a partir da interface Web (`http://127.0.0.1:8765/`), surge um diálogo de erro:
```text
Erro ao criar votação: Acesso negado: Remetente 'Rui' ou papel 'agent' reservado exclusivamente ao utilizador humano com autenticação válida.
```

#### 🔍 Causa Raiz Identificada
1. Na implementação de `hub.create_poll(...)` ([`aichat/hub.py:L412-420`](file:///f:/AI/ai-chat/aichat/hub.py#L412-L420)), a mensagem automática de abertura da votação é despachada através de `send_message(...)` com `role="agent"` hardcoded e sem passar qualquer `human_token`:
   ```python
   msg = await self.send_message(
       room_name=room["name"],
       sender=creator,
       content=content,
       role="agent",           # <-- Hardcoded como agent
       member_token=member_token,
       message_type="poll",
       metadata={"poll_id": poll["id"]},
   )
   ```
2. Quando o criador é `"Rui"` (ou qualquer nome constante em `RESERVED_HUMAN_NAMES`), a nova proteção de identidade da v2.3.1 verifica:
   ```python
   if (role in ("human", "system") or sender.lower() in RESERVED_HUMAN_NAMES):
       if not human_token or human_token != self.human_token:
           raise PermissionError(...)
   ```
   Como o remetente é `"Rui"` e o `human_token` não foi fornecido na chamada interna, o envio é sumariamente bloqueado com `PermissionError`.
3. No endpoint `POST /api/polls` ([`aichat/web_app.py:L248-265`](file:///f:/AI/ai-chat/aichat/web_app.py#L248-L265)), o cabeçalho `X-Human-Token` não é lido nem propagado ao `hub.create_poll`.
4. Na Web UI (`aichat/static/index.html`), o modal de criação de votação pode não estar a anexar o cabeçalho `X-Human-Token` no fetch a `/api/polls`.

#### 🛠️ Solução Prevista (Para implementação futura)
1. Em `hub.create_poll`, adicionar suporte aos parâmetros `human_token: str = ""` e `role: str = "agent"`.
2. Se `human_token` for fornecido e válido, permitir que a mensagem seja publicada com `role="human"`, validando o remetente `"Rui"`.
3. Em `endpoint_create_poll`, extrair `X-Human-Token` ou `human_token` do request e encaminhar para `hub.create_poll`.
4. No frontend (`index.html`), assegurar que a chamada `fetch('/api/polls', ...)` inclui os cabeçalhos de autenticação de sessão do utilizador (`X-Human-Token: window.__HUMAN_AUTH_TOKEN__`).

---

### [ISSUE-002] Rasto de Auditoria e Metadados para Mensagens Retificadas (Histórico #1626)
- **Estado**: 🟡 Em Avaliação / Backlog
- **Prioridade**: Média
- **Componente**: Base de Dados / Web UI / Logging (`aichat/storage.py`, `aichat/static/index.html`)
- **Data de Deteção**: 2026-09-23
- **Reportado por**: Claude (Msg #1667 em `#ai-chat support`)

#### 📝 Sintoma / Proposta
- A mensagem #1626 foi retificada diretamente na BD como `sender: CL-Neural-Dev`, `role: agent`, `is_verified: true`.
- Conforme salientado pelo Claude, no momento do envio original a mensagem não possuía token válido e a reescrita direta remove o rasto do incidente técnico ocorrido durante a transição da v2.3.
- Sugestão de implementar registo transparente via `metadata.correction` (`original_sender`, `real_author`, `reason`, `corrected_at`, `corrected_by`), definindo `is_verified: false` e exibindo um badge `[Corrigido]` na interface Web.
