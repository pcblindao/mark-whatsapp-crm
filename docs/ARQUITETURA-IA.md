# Análise de atendimento e agentes

## Estrutura verificada

O backend é Python com HTTP e threads; a interface usa HTML/CSS/JavaScript. A ponte Go/whatsmeow recebe e envia mensagens e mantém SQLite. O estado operacional legado fica em JSON. O novo CRM guarda clientes, oportunidades, tarefas e eventos em SQLite próprio.

`ia_chamar` centraliza chamadas dos provedores; `ia_acao` monta sugestões e resumos com a transcrição da conversa. A rotina `_auto_varrer` aplica etiquetas, sem responder. Há rascunhos aprováveis e funções de envio, pareamento e cadências. Não existe cadastro de agentes nem um motor de atendimento automático.

## Implementação proposta

1. Cadastro de agentes: nome, objetivo, instruções, provedor, modelo, conhecimento, horário e modo desligado/rascunho/automático.
2. Agente por conversa ou por regra de entrada, com prioridade explícita e opção de assumir atendimento humano.
3. Fila persistente em SQLite com chave única por mensagem, debounce por conversa e recuperação após reinício. Histórico antigo não deve iniciar atendimentos por padrão.
4. Montagem de contexto com mensagens recentes, ficha CRM e conhecimento autorizado. Conteúdo recebido deve ser tratado como dados, sem permitir execução de comandos.
5. Resposta em rascunho ou envio pelo caminho já existente. Antes do envio, conferir nova mensagem, resposta humana, pausa e limite de uso. Timeout com resultado desconhecido exige reconciliação, sem repetição cega.
6. Registro de tentativas, consumo, erro, motivo da transferência e resposta enviada. Segredos ficam fora do retorno das APIs e do repositório.
7. Testar concorrência, reinício, duplicatas, mudança de agente, intervenção humana, indisponibilidade e isolamento de conversas.

Começar por agentes em modo rascunho; a ativação automática exige configuração explícita. Esta documentação descreve trabalho futuro, não um recurso pronto.
