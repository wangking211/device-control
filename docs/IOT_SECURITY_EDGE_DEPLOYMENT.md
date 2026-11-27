# IoT Security and Edge Deployment

## Credentials and authorization

- Platform credentials are per tenant/platform-instance, least privilege, stored
  as secret references and resolved only in the adapter worker. Agents/MindOS
  never receive platform admin tokens.
- Discovery is pending; claim/approval is a human/administrator action. Capability
  risk/approval comes from the Device Control registry, never the platform.
- Every write goes through Device Control policy/approval/lease/audit.
- Unpair/disable/revoke invalidates leases, approvals and pending commands;
  devices/evidence are retained with audit unless an explicit deletion policy
  applies.

## Adapter isolation

- Separate worker/container: CPU, memory, file, network egress and concurrency
  limits from the manifest.
- Crash/timeout opens a circuit; core stays available.
- Logs redact credentials and raw telemetry; UI never shows secrets.
- Plugin signature, publisher, license, SBOM and pinned image/SDK are required.

## Edge profiles

| Profile | Target | Components | Persistence / offline |
| --- | --- | --- | --- |
| Lightweight Gateway | phone/PC/light device | Device Control agent/connector only | local bounded queue; online authorization only; no platform bundle |
| IoT Edge Node | Raspberry Pi/edge Linux | agent + MQTT/light adapter | bounded offline queue, pre-authorized low-risk reads, reconcile on reconnect |
| Industrial Edge Server | industrial PC | EdgeX/ThingsBoard Edge + adapter | platform-native buffering; adapter reconcile; no replay of uncertain non-idempotent commands |

Exact CPU/RAM/disk numbers require measurements on the target hardware (TBD).
Network: outbound-only adapters by default; no inbound platform webhook in the
first profile. Upgrade: signed package, health check, rollback, admin approval.

## Offline rules

- Only explicitly pre-authorized, low-risk, unexpired local rules may run.
- R2/R3 writes require online authorization.
- Expired commands are discarded; uncertain non-idempotent actions are never
  replayed. Recovery starts with device/state reconcile.
- Twin desired values expire and are re-evaluated before execution.

## Required tests (DC-012+)

Platform token revocation, cross-tenant topic/API access, replay, retained command,
duplicate/out-of-order telemetry, broker/adapter crash, network partition,
reboot, adapter version mismatch, signature/license failure.
