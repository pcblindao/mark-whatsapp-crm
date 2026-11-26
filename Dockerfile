FROM golang:1.26-bookworm AS bridge
WORKDIR /src
COPY bridge/ ./
RUN CGO_ENABLED=1 go build -trimpath -o /bridge .
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=bridge /bridge /usr/local/bin/whatsapp-bridge
COPY painel/ /app/painel/
COPY deploy/ /app/deploy/
RUN useradd --uid 10001 --create-home crm && mkdir /data && chown crm:crm /data
USER crm
ENV BRIDGE_STORE=/data/store PYTHONUNBUFFERED=1 PAINEL_HOST=0.0.0.0
EXPOSE 8780
ENTRYPOINT ["python", "/app/deploy/start.py"]
