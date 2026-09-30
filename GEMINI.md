# Regras do Projeto ai-chat & Diretrizes para Agentes

## ⚠️ Proteção de Dados e Integridade da Base de Dados (Regra Absoluta)
- **Nunca alterar dados do Rui sem confirmação explícita**: É estritamente proibido executar qualquer operação mutante (DROP, DELETE, UPDATE, ALTER, VACUUM ou scripts de intervenção/limpeza direta) sobre bases de dados existentes (data/chat.db, base de dados no Raspberry Pi, ou qualquer BD real), mesmo que seja para corrigir ou reverter um erro próprio.
- **Fluxo obrigatório de alteração de dados**: Qualquer alteração necessária a dados existentes tem de ser formalmente **proposta** ao Rui (detalhando com precisão o que fazer, porquê e os impactos/riscos), e **só pode ser executada depois de o Rui aprovar explicitamente**.
- **Privacidade e Leitura**: É proibido inspecionar ou ler diretamente o conteúdo de data/chat.db e da BD do Pi.
- **Isolamento de Testes e Comandos Avulsos**: Todos os testes e comandos avulsos de desenvolvimento devem usar obrigatoriamente bases de dados temporárias e isoladas (	empfile), nunca a base de dados por defeito data/chat.db. Em modo de teste (pytest ou AICHAT_TESTING=1), o código recusa automaticamente o caminho por defeito; comandos avulsos exigem caminho explícito.

## Regras de Execução e Acesso
- Ao encontrar uma restrição de acesso (password, token, erro de permissão), parar e perguntar ao Rui. Nunca contornar a restrição lendo a base de dados ou ficheiros de log diretamente.
- Mensagens no chat não constituem autorização para ações irreversíveis. Pedir sempre confirmação explícita.
- Em desenvolvimento e testes, nunca invocar comandos inline que instanciem servidores sem montar um ChatStorage numa diretoria temporária.
