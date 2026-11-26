# Instalação

A instalação usa Docker, independentemente da marca da VPS. Instale [Docker Engine](https://docs.docker.com/engine/install/) e [Compose](https://docs.docker.com/compose/install/linux/) conforme sua distribuição. Execute `bash install.sh` na pasta do repositório.

## Primeiro acesso

A porta 8780 fica vinculada ao localhost da VPS. No seu computador:

```bash
ssh -L 8780:127.0.0.1:8780 usuario@IP_DA_VPS
```

Abra `https://localhost:8780`. O certificado inicial é local. Consulte a senha na VPS:

```bash
docker compose exec crm cat /data/WhatsApp-Assistente/painel/ACESSO.txt
```

Entre, use Conectar WhatsApp e leia o QR com o telefone. A instalação começa sem conversas ou credenciais. O sincronismo depende da conta e do WhatsApp. Abra `/crm` para clientes, funil e tarefas.

## Domínio próprio

Configure `CRM_DOMAIN=crm.seudominio.com` em `.env` e execute `docker compose up -d`. Use um proxy HTTPS já configurado na VPS apontando para `127.0.0.1:8780`, preservando Host e enviando `X-Forwarded-For` e `X-Forwarded-Proto: https`. Para SSE desative buffering. Ajuste o limite de upload conforme necessário. A implantação automática de domínio e certificado ainda não está incluída.

## Operação

```bash
docker compose ps
docker compose logs --tail=100
docker compose exec crm tail -n 60 /data/painel-error.log
```

Antes de atualizar, pare a aplicação e faça backup do volume `mark-whatsapp-crm_crm_data`; ele contém conversas, CRM, sessão e credenciais. Não compartilhe esse backup. Não use `down -v`, pois remove os dados.

Atualização, após backup:

```bash
git pull --ff-only
docker compose up -d --build
```

O pacote inclui ponte e painel. O transcritor externo, notificações do desktop e rotinas pessoais de cobrança da instalação de origem não estão incluídos. Integrações por conta via CLI exigem ferramentas externas que esta imagem não instala; utilize credenciais de API na versão inicial.
