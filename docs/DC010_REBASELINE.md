# DC-010 Rebaseline

Date: 2026-11-27. Reviewed baseline in the task pack: device-control
`7187460`, mind-os `93af90c`, ai-platform `aa08cea`.

| Repo | Local HEAD | origin/main | Working tree |
| --- | --- | --- | --- |
| device-control | `718746005827f8a371f10f631951d07dc38342aa` | same | clean at start |
| mind-os | `93af90c5d8edeb19586eefea3b4f91e401080279` | same | two pre-existing untracked docs/local-dev entries; source clean |
| ai-platform | `932cc0a0bcfc2d360ea5f21c29485c49662bf5b2` | `592c71b8b3f27d1d6c5f05aeb19e86f9ec0c9be4` | pre-existing dirty tree; not rebased |

`ai-platform` moved since the pack baseline and is dirty. It was fetched but
not pulled/rebased to avoid mixing unrelated work. Its reusable storage package
was inspected at `platform/packages/foundation-storage`.

## Actual interfaces found

| Owner | Interface | Evidence |
| --- | --- | --- |
| MindOS | `mindos_contracts.device_control.DeviceCommandIntent/Result/TelemetryEvent` | `products/mind-os/packages/contracts/mindos_contracts/device_control.py` |
| MindOS | `PhysicalAction.command_intent()` | `products/mind-os/edge-agent/connectors/physical_world_intelligence.py` |
| MindOS | Provider Runtime registry (`ProviderDescriptor`, `ProviderInstance`) | `apps/api-gateway/app/agent_node/api/provider_registry.py` |
| ai-platform | `ObjectStorage` port, `LocalObjectStorage`, `S3ObjectStorage`, `storage_from_env` | `platform/packages/foundation-storage` |
| ai-platform | identity/scoped service tokens | `platform/packages/foundation-auth` |
| device-control | command/approval/lease/manifest/evidence APIs and OpenAPI | `contracts/openapi-v1.json` |

## Field/behavior differences to close

| Topic | MindOS | Device Control | Action |
| --- | --- | --- | --- |
| command id | intent has its own `command_id` | generated `command_id`, external `correlation_id` | Map intent id to `correlation_id`; store returned id as TaskRun `device_command_ref` |
| device id | `device_id` | `endpoint_id` + `device_id` + fingerprint | Provider resolves endpoint from device; Device Control owns binding |
| capability/operation | separate strings | manifest capability + operation | Send both; Device Control/gateway derive operation from manifest and reject mismatch |
| approval | `approval_ref` only | `approval_id` + one-time `approval_nonce` + state | Provider requires nonce from approval response; legacy shape cannot supply it |
| timeout | seconds | absolute deadline | Convert |
| status | free string | explicit state machine | Mapping preserves `waiting_approval`/`uncertain`; `executed_unverified` maps to `uncertain` + flag |
| evidence | not in legacy contract | opaque evidence metadata/content API | Store opaque refs; read content through authorized API |

## Device Control gaps found

- Screenshot path returned `redacted=True` without real redaction; server trusted
  a self-reported status.
- Gateway policy trusted upstream `policy_decision` for write approval.
- Manifest production signature was HMAC-only; no Ed25519/key id/window.
- UI quality/target uniqueness and future timestamps were weakly checked.
- Evidence routes instantiated the local store directly; no storage DI.
- Backup existed but no restore verification tool.
- Compose gateway used non-loopback HTTP while config rejected it.
- OpenAPI drift needed pinned generation environment.

## ai-platform reuse decision

`foundation-storage` is the existing object storage layer and is adopted behind
a small adapter when installed (`DEVICE_CONTROL_EVIDENCE_BACKEND=foundation`).
Standalone device-control keeps the local adapter for dev/test; no third storage
implementation is created. If `foundation` is selected and unavailable, upload
health is unavailable rather than silently falling back to local.

## TBD / blocked

- MindOS live Provider registration against a running API gateway: **BLOCKED**
  (no running MindOS API/DB in this environment). Adapter/descriptor and
  contract tests are delivered.
- Android real device: **BLOCKED** (no adb/emulator/device).
- Docker/TLS/mTLS: **BLOCKED** (no Docker daemon/ingress certificates).
- Real object storage (S3/COS): **BLOCKED** (no bucket/credentials). The
  adapter uses the existing foundation-storage interface.
