#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v docker >/dev/null || { echo 'Instale Docker Engine: https://docs.docker.com/engine/install/'; exit 1; }
docker compose version >/dev/null || { echo 'Instale o plugin Docker Compose.'; exit 1; }
docker info >/dev/null
if [ ! -f .env ]; then (umask 077; cp .env.example .env); fi
docker compose config --quiet
docker compose up -d --build
echo 'Mark WhatsApp CRM iniciado. Consulte docker compose logs e docs/INSTALACAO.md.'
echo 'Acesso inicial por túnel SSH: ssh -L 8780:127.0.0.1:8780 usuario@IP_DA_VPS'
echo 'Abra https://localhost:8780. Senha: docker compose exec crm cat /data/WhatsApp-Assistente/painel/ACESSO.txt'
