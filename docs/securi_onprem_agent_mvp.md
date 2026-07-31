# SecuRI On-Prem Agent MVP

## Objetivo

Conectar infraestructura on-premise del cliente con SecuRI sin abrir puertos entrantes hacia la red del cliente.

Modelo recomendado:

```text
Sistemas on-prem -> SecuRI On-Prem Agent -> HTTPS 443 outbound -> SecuRI SaaS
```

## Qué incluye este MVP

### Backend SecuRI

Se agregan endpoints protegidos por token:

```text
POST /api/agents/heartbeat
GET  /api/agents/config
POST /api/ingest/events
POST /api/ingest/batch
```

Autenticación soportada:

```text
Authorization: Bearer <token>
X-SecuRI-Agent-Token: <token>
```

Variable de entorno requerida en SecuRI:

```bash
SECURI_AGENT_INGEST_TOKEN="un-token-largo-y-seguro"
```

Fallback compatible:

```bash
SECURI_WEBHOOK_SECRET="un-token-largo-y-seguro"
```

### Agent on-prem

Ubicación:

```text
agents/onprem/securi_onprem_agent.py
agents/onprem/config.example.json
```

El agente soporta:

- Heartbeat hacia SecuRI.
- Lectura tipo tail de archivos de log.
- Syslog UDP local, recomendado puerto 5514 para no requerir root.
- Envío de batch hacia SecuRI.
- Comunicación outbound HTTPS.

## Licenciamiento

El endpoint valida la licencia de la empresa usando el modelo actual.

| Plan | On-prem/integraciones |
|---|---:|
| SecuRI Essential | 0 |
| SecuRI Professional | 1 |
| SecuRI Business | 2 |
| Enterprise / Custom | Negociado |

Las empresas existentes conservan sus límites guardados en base de datos.

## Instalación rápida del agente en Linux

```bash
mkdir -p /opt/securi-agent
cd /opt/securi-agent

# copiar securi_onprem_agent.py y config.json
chmod +x securi_onprem_agent.py
python3 securi_onprem_agent.py --config config.json
```

## Ejemplo de configuración

```json
{
  "api_url": "https://YOUR-SECURI-DOMAIN",
  "token": "CHANGE_ME_AGENT_TOKEN",
  "company_id": 12,
  "agent_id": "agent-hn-tgu-01",
  "batch_size": 100,
  "flush_interval_seconds": 30,
  "heartbeat_interval_seconds": 60,
  "sources": [
    {
      "type": "file",
      "enabled": true,
      "name": "linux-auth-log",
      "path": "/var/log/auth.log",
      "follow_from_end": true,
      "default_severity": "medium"
    },
    {
      "type": "syslog_udp",
      "enabled": true,
      "name": "firewall-syslog",
      "listen_host": "0.0.0.0",
      "listen_port": 5514,
      "default_severity": "medium"
    }
  ]
}
```

## Configurar un firewall para enviar syslog

El firewall debe enviar syslog al servidor donde corre el agente:

```text
Destino: IP_DEL_AGENT
Puerto: 5514 UDP
Formato: Syslog estándar
```

## systemd service recomendado

Crear archivo:

```bash
sudo nano /etc/systemd/system/securi-agent.service
```

Contenido:

```ini
[Unit]
Description=SecuRI On-Prem Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/securi-agent
ExecStart=/usr/bin/python3 /opt/securi-agent/securi_onprem_agent.py --config /opt/securi-agent/config.json
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
```

Activar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable securi-agent
sudo systemctl start securi-agent
sudo systemctl status securi-agent
```

## Prueba rápida sin agente

Heartbeat:

```bash
curl -X POST "https://YOUR-SECURI-DOMAIN/api/agents/heartbeat" \
  -H "Authorization: Bearer CHANGE_ME_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "company_id": 12,
    "agent_id": "agent-hn-tgu-01",
    "hostname": "collector01",
    "version": "2026.07-mvp",
    "status": "online"
  }'
```

Batch:

```bash
curl -X POST "https://YOUR-SECURI-DOMAIN/api/ingest/batch" \
  -H "Authorization: Bearer CHANGE_ME_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "company_id": 12,
    "agent_id": "agent-hn-tgu-01",
    "source_type": "syslog",
    "events": [
      {
        "source_type": "syslog",
        "source_name": "fortigate-fw01",
        "severity": "high",
        "event_name": "Denied inbound connection",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.10.10.20",
        "raw_event": {
          "action": "deny",
          "policy": "WAN-to-LAN"
        }
      }
    ]
  }'
```

## Resultado esperado

SecuRI crea un `AnalysisReport` por batch recibido. El reporte conserva:

- eventos normalizados,
- `agent_id`,
- `source_type`,
- severidades,
- score de riesgo,
- raw events.

También registra auditoría en `audit_logs` con acciones:

```text
ONPREM_AGENT_HEARTBEAT
ONPREM_AGENT_EVENT_INGEST
ONPREM_AGENT_BATCH_INGEST
```

## Fases siguientes

1. Panel en UI para crear/rotar tokens de agentes.
2. Modelo de base de datos `OnPremAgent` para inventario de agentes.
3. Windows Event Log collector.
4. SQL Server audit collector.
5. Buffer persistente local en SQLite para tolerar caídas largas de Internet.
6. Enriquecimiento automático con IA/correlación al recibir batches.
