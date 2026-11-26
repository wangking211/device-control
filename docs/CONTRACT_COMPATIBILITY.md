# Contract compatibility

The canonical shared schemas for this repository are maintained in `ai-platform/platform/contracts/device/`. This standalone repository vendors the same v1 files under `contracts/v1/` so a checkout remains buildable without a monorepo path dependency.

When changing a contract, update both repositories in one compatibility review. `contract_version: v1` is the wire major; additive optional fields are compatible, while required-field or enum removals/changes require a new major path. The service does not infer authorization from these schemas.
