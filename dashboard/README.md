# SentinelMesh AI dashboard

React and TypeScript operator interface for the SentinelMesh smart-home security simulator. It presents device telemetry, behavioral readiness, cyber and physical risk, correlated incidents, containment evidence, controller health, and a guided attack-and-recovery demo.

See the [main README](../README.md) for complete installation, service startup, API examples, configuration, and limitations.

## Local development

Start the simulator on port 8080 and the security engine on port 8081 first. From this directory:

```bash
npm ci
npm run dev
```

Open the URL printed by Vite (normally http://127.0.0.1:5173). Development proxies in `vite.config.ts` forward `/sim` to the simulator and `/sec` to the engine.

## Checks

```bash
npm test
npm run lint
npm run build
```

Use Node 22.12+ in the Node 22 line or a newer supported release such as Node 24. Tests use Node's TypeScript stripping. Build output is written to `dist/`.

`npm run preview` previews static build output. A deployed build requires API routing for `/sim` and `/sec`; the development proxy configuration is not bundled with the frontend.

## Source map

- `src/App.tsx`: main dashboard layout.
- `src/hooks/useDashboard.ts`: polling, operator actions, and guided demo coordination.
- `src/api.ts`: backend requests.
- `src/types.ts`: shared frontend data shapes.
- `src/components/`: dashboard panels and controls.
- `src/lib/`: interpretation/formatting helpers and unit tests.
- `src/index.css`: visual styling.

The autonomous enforcement worker runs in the Python security engine, so closing this UI does not stop backend defense.
