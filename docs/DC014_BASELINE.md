# DC-014 Baseline Audit (014-00)

Date: 2026-11-28
Task pack: `DC-014_Live_Device_Integration_MindOS_Task_Pack.zip`

## Repository baselines (fetched before changes)

| Repo | Branch | HEAD | origin/main | Worktree |
|---|---|---|---|---|
| `wangking211/device-control` | `main` | `e1e301af5aed0a31ccb7c28566ed811b43d2dc22` | same | clean |
| `wangking211/mind-os` | `main` | `0e9010ccd162da15d31ef7a0cdf741ba744f850d` | same | two untracked local files only (`.local-dev/`, `docs/mind-os/05-enterprise/DEVICE_CONTROL_D0_AUDIT_20261126.md`) |

Recent Device Control commits: DC-013 `e1e301a`, DC-012 `c0c3923`, DC-011 `d084475`.
Recent MindOS commit: `0e9010cc feat(DC-010): add Device Control provider adapter`.

The task-pack SHAs matched the live remote baselines exactly; no newer commit
was overwritten.

## Local verification at baseline

- `python -m pytest -q` in `products/device-control`: **126 passed**.
- Ruff: clean at baseline.
- mypy: previously reported clean; current environment has mypy 2.3.1 with
  newer `cryptography` stubs that flag pre-existing `public_key.verify`
  union-attr usage in `iot/manifest.py` and `app.py`. This is dependency-stub
  drift, not a DC-014 code change; tracked as an environment issue.
- pip-audit / Bandit: DC-013 evidence remains valid; rerun after changes.

## CI status — BLOCKED

`gh` CLI and `GITHUB_TOKEN`/`GH_TOKEN` are not available in this environment,
so the historical MindOS run `45987234028` job logs and current required-check
status cannot be fetched. Per the task-pack rules this item is **BLOCKED**, not
PASS. It must be closed from a machine with GitHub access; do not delete or
weaken workflows, tests or scans to make it green.

## Gap audit against existing code

| Task | Current state | Gap |
|---|---|---|
| 014-01 worker binding | HA pilot worker compared endpoint/device only when present; ignored tenant; platform check optional; `entity_bindings=None` skipped mapping entirely | Rewrite to mandatory, versioned binding registry |
| 014-02 state contract | Device Control internal states; MindOS had an independent `STATUS_MAP` (`uncertain→uncertain`, `timed_out→failed`) | Add one canonical projection, preserve raw provider status |
| 014-03 provider registry | MindOS `DeviceControlProvider.descriptor()` returns metadata but is not a runtime-registry entry | Catalog entry + factory + health lifecycle + SSRF guard |
| 014-04 TaskRun E2E | No live MindOS TaskRun → Device Control run | BLOCKED without running services |
| 014-05 WS pipeline | WebSocket primitives exist; not wired to persistence | Durable cursor/dedupe/ingest pipeline |
| 014-06 telemetry/twin | Telemetry dedupe and late-data handling exist | Add event identity/provenance, freshness and bounded queries |
| 014-07 claim UI | API claim/read-only exists; no UI | BLOCKED (no frontend runtime here) |
| 014-08 Docker + HA E2E | Compose file exists; Docker daemon unavailable | BLOCKED |
| 014-09 Android E2E | No emulator/device | BLOCKED |
| 014-10 production gates | Write features remain disabled by default | BLOCKED pending live drills |

## Constraints carried forward

- Device Control remains the only command authority; MindOS never writes device
  state directly and never owns a second Policy/Command/Twin/Evidence store.
- Real device writes stay disabled until DC-010/DC-014 production gates pass.
- No scanner, test or workflow may be disabled to obtain a green check.
