# Home Assistant Pilot Specification (DC-011 → DC-012)

Home Assistant 2026.11.x is the first platform pilot. It is not a Device Control
core dependency and MindOS never calls HA directly.

## Verified interface (2026-11-27)

- REST under `/api/` on port 8123 (80 under Supervisor); Bearer long-lived token.
- `GET /api/`, `/api/config`, `/api/states`, `/api/states/<entity_id>`,
  `GET /api/services`, `POST /api/services/<domain>/<service>`; SSE
  `/api/stream`; WebSocket `/api/websocket` for event subscriptions.
- Service call returns changed states, but that is not proof the physical goal
  occurred; re-read the entity state and verify.
- HA local automations continue offline; Device Control must reconcile after HA
  restart/reconnect.
- Token scope: long-lived user token; a dedicated least-privilege user/token is
  required. The token is a `secret_ref`, never in a manifest/log/UI.

## Mapping

| HA | Device Control |
| --- | --- |
| Device/Entity | Device + Endpoint (entity is an endpoint) |
| Entity state/attributes | Observation/Properties/Twin reported/observed |
| Area | Location/DeviceGroup |
| Domain/service | Capability + native operation |
| Service call | Command after policy/approval/lease |
| State re-read | postcondition verification |

Fixture: `fixtures/home_assistant_states.json`. Mapping helper:
`device_control.iot.home_assistant`.

## Discovery/claim

1. Adapter lists states/entities with cursor.
2. Each entity becomes a canonical device with `trust_state=pending`; no write
   capability is executable.
3. User/admin claims and approves the device (DC-012 API/UI).
4. Only then can an agent request a write; policy/approval still applies.

## Command/verification

- `light.set_state` maps to `light.turn_on/off/toggle`; `sensor` is read-only.
- Unknown domain/operation or a state mismatch is rejected.
- `service accepted`, `state changed` and `physical goal verified` are separate.
  If the state does not reach the expected value, command is `executed_unverified`
  or `uncertain`, never `succeeded`.

## Failure cases

HA offline/unavailable, token revoked, entity renamed/deleted, area change,
duplicate/out-of-order events, HA restart, network partition. Reconcile mapping
and state; do not replay expired/uncertain non-idempotent commands.

## Demo script (DC-012, synthetic fixtures only)

1. Discover `light.kitchen` and `sensor.living_room_temperature`; both pending.
2. Claim/trust both; temperature telemetry is readable.
3. MindOS requests light on; Device Control authorizes; adapter calls HA; re-read
   state is `on`; evidence/result verified.
4. Approval-required capability remains blocked before approval; deny leaves HA
   state unchanged.
5. HA unavailable → explicit failed/uncertain; no direct MindOS→HA call.

Non-goals: real locks, alarms, gas valves, medical devices; do not auto-convert
all entities into executable capabilities; no HA token in MindOS/browser.

## DC-012 implementation tasks

- Platform/Adapter/Device tables + migrations with consumers.
- Adapter worker using REST/WebSocket; secret resolver; rate/backoff; token
  revocation; mapping conflict policy.
- Claim/approve UI/API and capability registry; telemetry/twin ingestion.
- Live HA instance E2E (BLOCKED until an HA instance is provided).
