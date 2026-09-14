# SentinelMesh AI

SentinelMesh AI is a local smart-home cybersecurity demo that connects behavioral anomaly detection to simulated physical consequences and autonomous containment. It learns how virtual IoT devices normally behave, detects suspicious activity, explains the risk, and applies defensive actions to the simulated home.

The repository is named **SentinelMash-AI**; the application uses **SentinelMesh AI**.

## What it does

- Generates network, command, firmware, power, and device-state telemetry for a virtual residence.
- Builds per-device behavioral profiles and combines Isolation Forest, statistical, and cluster-distance detectors with heuristic signals.
- Classifies threats and produces risk scores, explanations, and recommended responses.
- Estimates simulated physical consequences, including forced entry, privacy loss, unsafe temperatures, and electrical hazards.
- Correlates evidence across devices into a potential entry-attempt incident.
- Enforces permission restrictions, network isolation, and device-specific safe modes in the simulator.
- Shows containment evidence, controller health, device details, incidents, and recovery in a live dashboard.

No physical hardware, cloud account, external AI API, or API key is required. The AI layer uses local anomaly models and programmed explanation/risk logic; it does not call an LLM.

## Architecture

```text
React dashboard (localhost:5173)
    | /sim proxy                       | /sec proxy
    v                                  v
IoT simulator (:8080) <---------- Security engine (:8081)
    |                   containment    |
    +---------------- telemetry ------>+
                           backend controller worker
```

The simulator produces telemetry every two seconds by default. The engine's background controller polls it, builds profiles, analyzes samples, and sends containment actions back. The dashboard observes this loop and provides operator controls. Closing the browser does not stop the controller; stopping the security-engine process does.

All simulator state, learned profiles, findings, and response history live in memory. Restarting the relevant service clears that service's state.

### Virtual home

| Device | Device ID | Room |
| --- | --- | --- |
| Front door camera | `cam-front-door` | Entryway |
| Front door lock | `lock-front-door` | Entryway |
| Lamp smart plug | `plug-living-lamp` | Living room |
| Thermostat | `thermo-hallway` | Hallway |

## Requirements

- Python **3.11 or newer** and pip.
- Node.js **22.12 or newer in the Node 22 line**, or a newer supported Node release such as Node 24, plus npm. The frontend uses Vite 8 and its tests use Node's TypeScript stripping.
- Git and a modern browser.
- Three terminals: one for each running service.

The commands below use macOS/Linux shell syntax. On Windows PowerShell, replace `source .venv/bin/activate` with `.venv\Scripts\Activate.ps1` and set environment variables using `$env:NAME="value"`.

## Install

```bash
git clone https://github.com/tounuage/SentinelMash-AI.git
cd SentinelMash-AI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cd dashboard
npm ci
cd ..
```

Python dependencies are declared with minimum versions. The dashboard includes a lockfile; `npm ci` installs its locked dependency tree.

## Start the application

Run Python commands from the repository root, with the virtual environment activated in each Python terminal.

**Terminal 1 — simulator**

```bash
source .venv/bin/activate
IOT_SIM_HOST=127.0.0.1 python -m iot_simulator
```

**Terminal 2 — security engine**

```bash
source .venv/bin/activate
ENGINE_HOST=127.0.0.1 python -m security_engine
```

**Terminal 3 — dashboard**

```bash
cd dashboard
npm run dev
```

Open **http://127.0.0.1:5173**. If that port is occupied, Vite may select another; use the URL printed in the terminal.

| Service | Interactive API documentation | Health |
| --- | --- | --- |
| Simulator | http://127.0.0.1:8080/docs | http://127.0.0.1:8080/api/v1/health |
| Security engine | http://127.0.0.1:8081/docs | http://127.0.0.1:8081/api/v1/health |

Wait for behavioral baselines to become ready before experimenting. The configured warmup is 12 samples, and individual detectors have their own sample requirements. Readiness is based on actual collected data, so it is not immediate.

Stop each process with **Ctrl+C**. To start a clean session, restart both Python services and reload the dashboard.

## Run the guided demo

1. Start all three services and open the dashboard.
2. Click **Run demo**. It resets the scenario and waits for normal-home baselines.
3. Watch the attack against the front door lock progress through detection and explanation.
4. Inspect the cyber risk, physical-entry forecast, response state, and containment evidence.
5. Watch safe mode block the hostile operation, followed by campaign shutdown and recovery.

Use the attack console for manual experiments. Select a target, attack type, intensity, and duration; then inspect the affected device and its response. Stop active attacks before requesting recovery, otherwise subsequent telemetry can trigger containment again.

To demonstrate backend autonomy, close the dashboard after warmup, inject an attack through the simulator API, and inspect the engine's findings and response endpoints. Reopening the dashboard displays the current backend state. The controller endpoint exposes `active`, `fresh`, `last_error`, `enforcement_enabled`, and cycle counters; health alone does not establish successful enforcement.

## API walkthrough

The examples use `curl` and the default ports. The `/docs` pages provide complete request and response schemas.

### Inspect the home and controller

```bash
curl http://127.0.0.1:8080/api/v1/devices
curl http://127.0.0.1:8080/api/v1/telemetry
curl http://127.0.0.1:8081/api/v1/controller
curl http://127.0.0.1:8081/api/v1/profiles
```

### Inject a simulated attack

```bash
curl -X POST http://127.0.0.1:8080/api/v1/attacks \
  -H 'Content-Type: application/json' \
  -d '{"attack_type":"unauthorized_commands","device_id":"lock-front-door","duration_seconds":60,"intensity":"high"}'
```

Supported attack types:

| Type | Simulated signal |
| --- | --- |
| `abnormal_network_traffic` | Unusual traffic volume/activity |
| `unauthorized_commands` | Commands outside permitted behavior |
| `suspicious_ip_connections` | Suspicious remote peers |
| `firmware_modification` | Changed firmware integrity |
| `abnormal_power_usage` | Abnormal power consumption |

Intensity accepts `low`, `medium`, or `high`. Duration is 5–3600 seconds. Omitting `device_id` lets the simulator select a compatible target. Suspicious endpoints use documentation address ranges such as `203.0.113.0/24` and `198.51.100.0/24`.

### Read detection and containment results

After a few controller cycles:

```bash
curl http://127.0.0.1:8081/api/v1/findings/lock-front-door
curl http://127.0.0.1:8081/api/v1/device/lock-front-door/response
curl http://127.0.0.1:8081/api/v1/incidents
curl http://127.0.0.1:8080/api/v1/telemetry/lock-front-door
```

Findings describe analysis; the response contains the defensive action; simulator telemetry shows the resulting simulated behavior. Use these together when checking containment.

### Stop attacks and recover

```bash
curl -X POST http://127.0.0.1:8080/api/v1/attacks/stop \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"lock-front-door"}'

curl -X POST http://127.0.0.1:8081/api/v1/device/recover \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"lock-front-door","force":false}'
```

Normal recovery can proceed through `MONITOR` before returning to `NORMAL`. The controller also evaluates recovery as risk falls. For reproducible guided runs, use **Run demo**, which coordinates resets and readiness checks.

### Other useful endpoints

All paths below have the `/api/v1` prefix.

| Service | Method and path | Purpose |
| --- | --- | --- |
| Simulator | `GET /telemetry/{device_id}/history?limit=50` | Recent telemetry |
| Simulator | `GET /attacks` | Active campaigns |
| Simulator | `POST /simulation/tick` | Produce an extra tick |
| Simulator | `POST /simulation/reset?demo=true` | Reset simulator into demo mode |
| Engine | `GET /detectors` | Registered detectors |
| Engine | `GET /findings` | Latest findings for the fleet |
| Engine | `GET /devices/responses` | Fleet response states |
| Engine | `POST /analyze` | Analyze a telemetry sample |
| Engine | `POST /analyze/batch` | Analyze a list of samples |
| Engine | `POST /analyze/snapshot` | Analyze an environment snapshot |
| Engine | `POST /ingest/simulator` | Pull and analyze simulator data manually |
| Engine | `POST /controller` | Set `enforcement_enabled` |
| Engine | `POST /reset` | Clear engine profiles, findings, and response state |

Manual analysis/ingest endpoints do not replace the worker's automatic enforcement cycle. Simulator and engine resets are separate operations.

## Response policy

| State | Score-based selection | Behavior |
| --- | --- | --- |
| `NORMAL` | Below 20 | Normal device activity |
| `MONITOR` | 20 to below 45 | Additional telemetry |
| `RESTRICTED` | 45 to below 75 | Permission reduction, suspicious-peer blocking, safe mode |
| `QUARANTINE` | 75 and above | Isolation with the controller channel retained |

Threat classification can impose a stricter minimum state: firmware modification and multi-stage compromise require quarantine. Escalation is immediate; recovery uses lower-risk evidence and staged transitions. See `security_engine/response/engine.py` for the exact policy.

## Configuration

Settings are read from environment variables. Export them before launching a service; there is no configured automatic `.env` file loading.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IOT_SIM_HOST` | `0.0.0.0` | Simulator bind address |
| `IOT_SIM_PORT` | `8080` | Simulator port |
| `IOT_SIM_TICK_INTERVAL_SECONDS` | `2.0` | Telemetry interval |
| `IOT_SIM_HISTORY_LIMIT` | `300` | Retained telemetry history |
| `IOT_SIM_COMMAND_HISTORY_LIMIT` | `25` | Retained command history |
| `ENGINE_HOST` | `0.0.0.0` | Engine bind address |
| `ENGINE_PORT` | `8081` | Engine port |
| `ENGINE_SIMULATOR_URL` | `http://127.0.0.1:8080` | Simulator address |
| `ENGINE_POLL_SIMULATOR` | `true` | Start background controller |
| `ENGINE_POLL_INTERVAL_SECONDS` | `2.0` | Controller polling interval |
| `ENGINE_HEARTBEAT_STALE_SECONDS` | `6.0` | Heartbeat freshness threshold |
| `ENGINE_WARMUP_SAMPLES` | `12` | Profile warmup size |
| `ENGINE_HISTORY_SIZE` | `180` | Profile history size |
| `ENGINE_ANOMALY_UPDATE_THRESHOLD` | `60.0` | Score threshold for baseline updates after warmup |
| `ENGINE_HEURISTIC_BLEND` | `0.4` | Heuristic scoring blend |

The startup commands above bind the APIs to localhost. If backend ports change, update the proxy targets in `dashboard/vite.config.ts`; if the simulator address changes, also set `ENGINE_SIMULATOR_URL`.

## Development and checks

From the repository root:

```bash
source .venv/bin/activate
python -m pytest
```

Frontend checks:

```bash
cd dashboard
npm test
npm run lint
npm run build
```

The Python suite covers simulator APIs, anomaly analysis, response policy, physical risk, containment verification, controller autonomy, mesh correlation, and demo repeatability. Frontend tests cover readiness, containment, controller status, physical consequences, and correlation helpers.

`npm run build` writes frontend assets to `dashboard/dist`. `npm run preview` previews the build, but the API proxies are configured for the development server only. A deployed build needs a reverse proxy for `/sim` and `/sec`, or corresponding API-client changes.

### Project layout

```text
SentinelMash-AI/
├── iot_simulator/
│   ├── api/             # FastAPI endpoints and lifecycle
│   ├── devices/         # Camera, lock, plug, thermostat models
│   ├── models/          # Typed telemetry and attack schemas
│   └── simulation/      # Environment, attacks, containment, verification
├── security_engine/
│   ├── api/             # Analysis and controller endpoints
│   ├── controller.py    # Autonomous polling/enforcement worker
│   ├── pipeline.py      # Analysis orchestration
│   ├── features/        # Telemetry feature extraction
│   ├── profiles/        # In-memory behavioral baselines
│   ├── detectors/       # Statistical and ML detectors
│   ├── correlation/     # Cross-device incident correlation
│   ├── scoring/         # Risk, threat, and physical-impact assessment
│   ├── response/        # Policy, explanations, effects, enforcement
│   └── ingest/          # Simulator HTTP client
├── dashboard/           # React, TypeScript, Vite, Tailwind UI
│   └── src/
│       ├── components/  # Operator views and controls
│       ├── hooks/       # Dashboard state and demo orchestration
│       └── lib/         # Presentation helpers and tests
├── tests/               # Python tests
├── requirements.txt
└── pyproject.toml
```

To add a detector, implement the `AnomalyDetector` interface and register it in `security_engine/detectors/__init__.py`. To add a device or attack, update the simulator models and environment, then extend feature extraction, response effects, dashboard types, and relevant tests as needed.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Dashboard cannot reach APIs | Confirm both Python processes are running and their `/api/v1/health` endpoints respond. Check Vite proxy ports. |
| Controller inactive | Ensure `ENGINE_POLL_SIMULATOR` is true and inspect `/api/v1/controller`. |
| Controller reports errors | Check `last_error`, simulator availability, and `ENGINE_SIMULATOR_URL`. |
| Models are not ready | Allow clean telemetry to accumulate; use Run demo to reset and warm up a controlled scenario. |
| Device stays restricted | Stop its attacks, inspect current risk, and allow recovery cycles or request recovery. |
| Python import/dependency error | Activate `.venv`, install requirements, and run from the repository root. |
| Node/Vite or TypeScript test error | Check the Node version, then run `npm ci` inside `dashboard`. |
| Port already in use | Stop the conflicting process or change service ports and matching proxy configuration. |
| Built frontend loads but API calls fail | Configure deployment proxies; Vite development proxies are not part of the static build. |

## Scope and limitations

This is a demonstration environment, not a production home-security product. Attacks, device behavior, physical outcomes, and enforcement are simulated; the application does not manage real locks, cameras, firmware, or firewalls. Physical-risk estimates illustrate the scenario and are not validated safety predictions.

The APIs currently have no authentication and allow broad CORS access. Keep the demo local. Production work would require authenticated access, restricted origins, persistent storage, deployment configuration, and validated hardware integrations. Baselines depend on observed telemetry and can be influenced by anomalous data during warmup.

No license file is currently included in this repository.
