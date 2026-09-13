# SentinelMesh AI

Autonomous cyber-physical immune system for a simulated smart home.

Unlike detector-only IoT tools, SentinelMesh:

1. Learns each device's normal behavior
2. Detects anomalies across network, power, firmware, and commands
3. Explains the threat in operator language
4. Predicts the **physical** consequence (forced entry, privacy loss, HVAC extremes, electrical fire)
5. Moves the device into a safe operating mode
6. Recovers the home once the campaign is over

The MVP uses a virtual residence because no physical hardware is required.

## Simulated home

| Device | ID | Room |
| --- | --- | --- |
| Front door camera | `cam-front-door` | Entryway |
| Front door lock | `lock-front-door` | Entryway |
| Living room lamp plug | `plug-living-lamp` | Living room |
| Hallway thermostat | `thermo-hallway` | Hallway |

## Product demo

The dashboard **Run demo** button walks this loop:

1. **Normal home** — devices match their learned baselines
2. **Attack** — hostile remote unlock against the front door lock
3. **AI detection** — anomaly models leave the envelope
4. **Explainable risk** — cyber narrative plus physical-entry forecast
5. **Safe mode** — lock forced shut, remote unlock revoked, untrusted peers blocked
6. **Recovery** — campaign stopped, device restored to normal

The security engine runs a **controller worker** that ingests telemetry, executes policy, and enforces containment even if the dashboard is closed. Judges can close the UI, inject the lock attack on the simulator, then reopen the dashboard to the recorded, verified response. **Controller active** is backed by the worker heartbeat, not a page-load health ping.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m iot_simulator          # http://127.0.0.1:8080/docs
python -m security_engine        # http://127.0.0.1:8081/docs  (controller worker starts here)

cd dashboard && npm install && npm run dev

cd dashboard && npm install && npm run dev
```

Open `http://127.0.0.1:5173`. The UI proxies `/sim` → `:8080` and `/sec` → `:8081`.

## Response states

| State | Behavior |
| --- | --- |
| `NORMAL` | Allow all activity |
| `MONITOR` | Extra packet, DNS, and command telemetry |
| `RESTRICTED` | Reduce permissions, block suspicious communication, enter safe mode |
| `QUARANTINE` | Isolate the device except the controller channel |

## Attacks

`POST /api/v1/attacks` on the simulator can inject:

- `abnormal_network_traffic`
- `unauthorized_commands`
- `suspicious_ip_connections`
- `firmware_modification`
- `abnormal_power_usage`

Suspicious endpoints use documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`).
