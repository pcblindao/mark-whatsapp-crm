# Mark WhatsApp CRM

**Atendimento no WhatsApp e gestão de clientes no seu servidor.**

Criado por **Marcos Roberto**. Distribuição gratuita. VPS e serviços de IA contratados pelo instalador podem ter custos próprios.

## Recursos

- Conversas, contatos, arquivos, etiquetas e respostas rápidas.
- Mensagens agendadas e acompanhamento de conversas.
- CRM: cadastro de clientes, oportunidades em seis etapas, valores, responsáveis, tarefas, prazos e histórico de alterações.
- Integrações existentes de IA para sugestões, resumos e correção de mensagens.

O cadastro e motor de agentes de atendimento automático ainda estão em planejamento. Consulte [a análise de implementação](docs/ARQUITETURA-IA.md).

## Instalar na VPS

Requer Linux com Docker Engine e Docker Compose. O provedor da VPS é livre. A primeira compilação precisa de internet e espaço para imagens e dependências. Esta versão inicial ainda precisa concluir a homologação em VPS limpa; não há garantia de compatibilidade com toda distribuição ou arquitetura.

```bash
git clone https://github.com/pcblindao/mark-whatsapp-crm.git
cd mark-whatsapp-crm
bash install.sh
```

Depois siga [acesso, senha e conexão do WhatsApp](docs/INSTALACAO.md). Para abrir o CRM, acesse `/crm` após entrar.

## Estado do projeto

Versão inicial de desenvolvimento. O CRM usa uma instalação e uma equipe com acesso compartilhado; usuários, permissões individuais e múltiplos números ainda não estão implementados. Os clientes podem guardar o identificador da conversa; abertura direta da conversa a partir da ficha está pendente.

A integração WhatsApp usa uma ponte baseada em whatsmeow, sem afiliação à Meta. A disponibilidade depende do protocolo do WhatsApp.

## Autoria e créditos

**Marcos Roberto — criador do Mark WhatsApp CRM.**

A ponte deriva de [whatsapp-mcp](https://github.com/lharries/whatsapp-mcp), de Luke Harries. A licença original está preservada em `licenses/whatsapp-mcp-MIT.txt`. Dependências mantêm suas próprias licenças.

Código original do Mark WhatsApp CRM: uso gratuito, conforme [LICENSE](LICENSE).
