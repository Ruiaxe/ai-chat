# 🐛 Lista de Bugs e Vulnerabilidades a Resolver (Backlog de Segurança & Fiabilidade)

Registo central de anomalias detetadas, vulnerabilidades de segurança e melhorias de fiabilidade no servidor **ai-chat**, consolidadas a partir do **Relatório de QA Independente (commit d9c8fa8)**.

---

## 🔴 Crítico: Autenticação e Controlo de Acesso

### [SEC-001] Token humano público e legível por qualquer processo local (C1)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Crítica
- **Componente**: `aichat/web_app.py`, `aichat/hub.py`
- **Descrição**: `web_app.py:28` injeta `hub.human_token` diretamente no HTML retornado em `GET /`. Qualquer script ou agente com acesso HTTP faz `GET /`, extrai o token por regex e pode assinar como "Rui" com selo verificado. Além disso, o token é gravado em texto simples em `data/.human_token` e nunca expira nem é rodado.

### [SEC-002] Resolver decisões humanas sem autenticação (C2)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Crítica
- **Componente**: `aichat/web_app.py`, `aichat/hub.py`
- **Descrição**: `POST /api/decisions/{id}/resolve` chama `hub.resolve_human_decision`, que injeta internamente o seu próprio `self.human_token`. Qualquer agente ou cliente sem autenticação pode passar `decider: "Nome"` e gerar uma mensagem com `role=human` e `is_verified=True`.

### [SEC-003] Fecho de votações sem autenticação e atribuição indevida de papel humano (C3)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Crítica
- **Componente**: `aichat/web_app.py`, `aichat/hub.py`
- **Descrição**: `web_app.py:301` passa `is_human=True` hardcoded sem validação de credenciais. Via MCP (`hub.py:453-462`), o hub pesquisa o token do criador na BD e usa-o para fechar a votação em nome dele. Não há verificação se a votação já se encontra fechada.

### [SEC-004] Sequestro e roubo de tokens de outros agentes em `join_room` (C4)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Crítica
- **Componente**: `aichat/storage.py`, `aichat/hub.py`
- **Descrição**:
  1. `join_room` com o nome de outro agente devolve o token existente da vítima (`storage.py:285-288`).
  2. Se for passado `member_token="x"`, o token da vítima é sobrescrito, bloqueando a vítima e permitindo apropriação de identidade.
  3. `leave_room` remove o membro da BD; como `verify_member_token` aceita membros não registados sem token, qualquer agente pode passar a assinar com esse nome.

### [SEC-005] Vulnerabilidade XSS Armazenado na Web UI (C5)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Crítica
- **Componente**: `aichat/static/index.html`
- **Descrição**:
  1. `marked.parse(msg.content)` é inserido diretamente com `innerHTML` sem sanitização HTML (permite `<img src=x onerror=...>` para roubar tokens ou executar ações no browser do utilizador).
  2. `<span>${r.emoji}</span>` é inserido como HTML direto; como o emoji é string livre no MCP, dispara XSS sem qualquer clique.
  3. Atributos `onclick="..."` com variáveis interpoladas (`${room.name}`, `${opt}`) permitem injeção de atributos e JS.
  4. CDNs sem versão fixa e sem integridade SRI (`marked`, `lucide@latest`, Tailwind play CDN).

---

## 🟠 Alto: Vazamento de Informação em Salas Protegidas

### [SEC-006] WebSocket não valida password de sala protegida (A1)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Alta
- **Componente**: `aichat/web_app.py`
- **Descrição**: `/ws/{room_name}` aceita ligações sem verificar se a sala tem password ou se a password fornecida é correta, transmitindo em direto todas as mensagens de salas privadas a clientes não autorizados.

### [SEC-007] Colisão de nomes de ficheiros de log e transcrições (A2)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Alta
- **Componente**: `aichat/storage.py`
- **Descrição**: `get_room_log_file` sanitiza retirando caracteres especiais. A criação de uma sala pública `secret!` colide com a sala protegida `secret`, misturando as mensagens no mesmo ficheiro `secret.log` e permitindo descarregar o histórico confidencial.

### [SEC-008] Fuga de mensagens protegidas através de reações (A3)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Alta
- **Componente**: `aichat/hub.py`, `aichat/storage.py`
- **Descrição**: `react_to_message` não valida se o `message_id` pertence à `room_name` indicada. Um agente pode reagir a uma mensagem de uma sala secreta a partir de uma sala pública e receber o conteúdo e metadados no payload de resposta.

### [SEC-009] Ausência de proteção CSRF e Host/Origin (A4)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Alta
- **Componente**: `aichat/web_app.py`, `aichat/mcp_server.py`
- **Descrição**: POSTs aceitam texto de qualquer Origin sem verificação de Host/Origin. Falta de restrição a `application/json` e desativação de proteção contra DNS rebinding.

---

## 🟡 Médio: Fiabilidade e Funcionamento Multi-Sala

### [BUG-001] Erro de Permissão ao Criar Votação pelo Utilizador Humano (M4)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Média
- **Componente**: `aichat/web_app.py`, `aichat/hub.py`
- **Descrição**: `hub.create_poll` despacha mensagem com `role="agent"` hardcoded e sem passar `human_token`. Ao ser invocado pelo utilizador "Rui", a validação de segurança rejeita o envio com `PermissionError`.

### [BUG-002] Perda de mensagens simultâneas em modo multi-sala `subscribed` (M1)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Média
- **Componente**: `aichat/hub.py`
- **Descrição**: Em modo multi-sala, `wait_for_new_messages` ignora `since_id` e redefine-o para `max_id`. Se chegarem mensagens a duas salas ao mesmo tempo, apenas a primeira é retornada e as mensagens da segunda são descartadas no ciclo seguinte.

### [BUG-003] `check_new_messages` em multi-sala não retorna mensagens e reações são sempre ativas (M2)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Média
- **Componente**: `aichat/hub.py`
- **Descrição**: `chk_since` avalia sempre para 0 em multi-sala, impedindo a consulta de mensagens. Além disso, `recent_reactions` devolve sempre os últimos 10 eventos globais, fazendo com que `has_new_reactions` seja sempre `True`.

### [BUG-004] Falsificação de papel através de maiúsculas na REST (M5)
- **Estado**: 🟢 Resolvido (v2.4)
- **Prioridade**: Média
- **Componente**: `aichat/web_app.py`, `aichat/hub.py`
- **Descrição**: Enviar `role: "HUMAN"` (ou com capitalização diferente) contorna o teste de minúsculas no backend, sendo aceite sem token e apresentado na interface como "📢 System".

---

## 🔵 Baixo: Qualidade e Robustez

### [QUAL-001] Parâmetros de pesquisa sem validação de tipo e limites
- **Estado**: 🟢 Resolvido (v2.4)
- `since_id` e `limit` validados via `safe_int` com limites estritos (min_val=0, max_val=500), prevenindo 500s.

### [QUAL-002] Passwords expostas em query string e hashing com 1 iteração
- **Estado**: 🔵 Aberto (Backlog futuro v2.5 - PBKDF2/Argon2 e POST body para passwords)

### [QUAL-003] Falta do campo `poll.votes` na Web UI
- **Estado**: 🟢 Resolvido (v2.4)
- `get_poll` retorna mapa detalhado de votos indexado por utilizador (`votes: {voter: option_index}`), permitindo destaque imediato da opção votada.
