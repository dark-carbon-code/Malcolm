# Malcolm Copilot UI

Dual-persona LLM interface for Malcolm network traffic analysis.

## Overview

The Copilot UI provides two analyst views over the same network capture data:

- **SOC Analyst** — alert triage, connection forensics, threat hunting
- **System Engineer** — process state, control loops, digital control surface exposure

The System Engineer view highlights digitally-exposed control paths that lack
independent non-digital safety barriers — the critical insight for OT/ICS
defenders working with Malcolm.

## Architecture

- **Standalone React/Vite app** served as a Docker container on port 3000
- **Talks to** `malcolm-llm-gateway` via REST (`GET /health`, `POST /chat`, `POST /tools/{name}`)
- **Falls back** to built-in mock data when the gateway is unavailable (demo mode)
- **Mock domain**: midstream gas compressor station — Solar Mars 100-16000S / C65 / Turbotronic 5 / ControlLogix

## Quick Start

```bash
# Local development (no gateway needed — runs on mock data)
cd copilot-ui
npm install
npm run dev
# Open http://localhost:3000
```

## Docker Build

```bash
# From the Malcolm repository root:
docker build -f Dockerfiles/copilot-ui.Dockerfile -t ghcr.io/idaholab/malcolm/copilot-ui:latest .
docker run -p 3000:3000 ghcr.io/idaholab/malcolm/copilot-ui:latest
```

## Docker Compose (with Malcolm)

```bash
# As a compose override alongside Malcolm's services:
docker compose -f docker-compose.yml -f copilot-ui/docker-compose.copilot.yml up copilot-ui
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_GATEWAY_URL` | LLM gateway base URL | _(empty = mock mode)_ |

Set in `copilot-ui/.env` or pass as environment variable.

## Demo Queries

### SOC Analyst View
1. **Top Talkers** — source IP volume analysis
2. **Beaconing Check** — connection interval regularity detection
3. **Suricata Triage** — alert severity/signature grouping
4. **OT Segmentation** — cross-zone traffic policy violations

### System Engineer View
1. **Process State** — compressor station operating parameters + control loop health
2. **Asset Inventory** — OT network assets with protocols and criticality ratings
3. **Exposed Control Paths** — digital paths to safety functions without non-digital barriers
4. **Correlate SSH + Process** — ties network anomaly to physical process risk assessment

## File Structure

```
copilot-ui/
├── .env                            # Gateway URL config
├── .gitignore                      # node_modules, dist, logs
├── docker-compose.copilot.yml      # Compose override for Malcolm stack
├── index.html                      # Vite HTML entry point
├── nginx.conf                      # Container nginx: SPA routing + /api proxy
├── package.json                    # react 18, vite 5
├── README.md                       # This file
├── vite.config.js                  # Build config with dev proxy
└── src/
    ├── App.jsx                     # Malcolm Copilot (1352 lines, fully documented)
    └── main.jsx                    # React root mount

Dockerfiles/
└── copilot-ui.Dockerfile           # Multi-stage: node build → nginx serve
```

## Gateway API Contract

The UI expects these endpoints from the gateway:

### `GET /health`
```json
{
  "status": "ok",
  "backend_mode": "replay",
  "model": "ollama:qwen2.5:7b-instruct",
  "replay_data_loaded": true,
  "version": "0.1.0"
}
```

### `POST /chat`
Request:
```json
{
  "session_id": "optional-string",
  "question": "text",
  "time_window": {"preset": "last_60m"},
  "ui_options": {"include_raw": false, "view": "soc"}
}
```

Response:
```json
{
  "session_id": "abc123",
  "answer": "markdown string",
  "evidence": [
    {
      "evidence_id": "ev-001",
      "tool": "os_top_values",
      "source": "replay",
      "time_range": {"start": "...", "end": "..."},
      "query": {},
      "summary": {},
      "exemplars": [{}]
    }
  ],
  "suggested_pivots": [
    {
      "pivot_id": "pv-001",
      "label": "description",
      "action": {"type": "tool|chat", "tool": "name", "args": {}}
    }
  ]
}
```

### `POST /tools/{tool_name}`
Generic tool runner. Request: arbitrary JSON args. Response: JSON with summary + exemplars.

## Taking This to Production

1. Extract mock data into gateway replay handlers
2. Wire asset inventory to Malcolm's Zeek logs + device profiling
3. Wire process state to Malcolm's Arkime sessions + OT protocol parsers
4. Control path analysis becomes a first-class Malcolm analytic
5. Add streaming support for `POST /chat` (SSE or WebSocket)
6. Break `App.jsx` into component files when the feature matures
7. Add to Malcolm's nginx-proxy upstream config for unified auth/TLS
