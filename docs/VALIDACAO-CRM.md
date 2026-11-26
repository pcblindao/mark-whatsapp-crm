# Validação do CRM — 26/11/2026

- Dez testes de persistência, validação, migração do banco anterior, conflito de edição, atualização parcial, arquivamento/restauração e valores de propostas passaram.
- Fluxo de interface em navegador sem janela: contato do WhatsApp, ficha, oportunidade, mudança de etapa por arraste, produto, proposta com desconto, tarefa e restauração passou. Dados fictícios usados somente no ambiente local.
- Layout revisado em 1440 px e 390 px; seis telas móveis verificadas sem transbordamento horizontal da página.
- Instalação online: menu CRM na área de filtros, formulário de proposta e seleção de contato verificados sem gravar registros de teste. Nenhum erro JavaScript observado.
- HTTP 200 para interface e API internas; sem sessão pública, 401; POST sem origem, 403.
- Backup dos arquivos e do SQLite feito antes da atualização; migração ensaiada em uma cópia do banco.

## Limites atuais

Logins individuais e permissões, múltiplos números, cobrança financeira, assinatura eletrônica e motor de agentes automáticos não estão implementados. Propostas são registradas e impressas; o sistema não envia uma proposta automaticamente. Relatórios usam registros ativos de todo o período. Importação CSV aceita até 200 clientes por arquivo, ignora coincidências por telefone/e-mail e informa o resultado parcial em caso de erro. Arquivamento preserva relações; não há exclusão permanente pela interface.

A instalação Docker em VPS limpa continua pendente de homologação. O modelo de workflow está em `docs/check.yml.example`, pois a credencial GitHub disponível não permite publicar workflows.

## Configurações, identidade e conversas

Dezesseis testes passaram, incluindo renomeação de coluna com preservação de oportunidades, recusa de remoção de coluna ocupada, validação de campos obrigatórios, desativação sem perda de valores e concorrência de configuração. Formulários e telas foram verificados com campos personalizados, padrões de proposta e os temas claro/escuro.

Integração testada com mensagens simuladas: consulta de mensagens, envio manual único, tarefa vinculada e nota registrada a partir da ficha no WhatsApp. Nenhuma mensagem real foi enviada nos testes. A interface online de configurações foi verificada sem modificar dados da empresa ou do funil.

As colunas ganhas e perdidas podem ser renomeadas; seus tipos orientam os relatórios. Remover uma coluna exige antes mover as oportunidades, inclusive arquivadas. Campos desativados preservam os valores; a alteração do tipo/módulo requer outro campo. A visualização de conversa no CRM apresenta as últimas 60 mensagens, com atualização a cada cinco segundos; anexos e demais ações continuam no WhatsApp completo.
