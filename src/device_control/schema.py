"""Versioned SQLite migrations.

The service previously created tables lazily with ``CREATE TABLE IF NOT
EXISTS``. That cannot upgrade an existing database, so this module applies
ordered, recorded migrations and adopts databases created by the old code
without losing endpoints, leases or approvals.

Each migration runs inside ``BEGIN IMMEDIATE`` together with its
``schema_migrations`` row, so a partially applied version is rolled back.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

LATEST_VERSION = 11


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]


ENDPOINTS = """
CREATE TABLE IF NOT EXISTS device_endpoints (
    endpoint_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    node_ref TEXT,
    gateway_id TEXT,
    credential_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('online','degraded','offline','revoked')),
    capabilities_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    credential_expires_at TEXT,
    credential_rotated_at TEXT,
    last_heartbeat_at TEXT,
    revoke_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
)
"""

LEASES = """
CREATE TABLE IF NOT EXISTS device_leases (
    lease_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES device_endpoints(endpoint_id),
    tenant_ref TEXT NOT NULL,
    task_ref TEXT NOT NULL,
    run_ref TEXT,
    holder_ref TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('read_only','control')),
    expires_at TEXT NOT NULL,
    released_at TEXT,
    holder_type TEXT,
    released_reason TEXT
)
"""

APPROVALS_NEW = """
CREATE TABLE IF NOT EXISTS device_approvals_next (
    approval_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    gateway_id TEXT NOT NULL DEFAULT '',
    lease_id TEXT NOT NULL,
    requester_ref TEXT NOT NULL,
    requester_type TEXT NOT NULL DEFAULT 'user',
    approver_ref TEXT,
    approver_type TEXT,
    action_digest TEXT NOT NULL,
    capability_id TEXT NOT NULL DEFAULT '',
    capability_version TEXT NOT NULL DEFAULT '',
    intent TEXT NOT NULL DEFAULT '',
    parameters_json TEXT NOT NULL DEFAULT '{}',
    state_hash TEXT,
    policy_version TEXT NOT NULL DEFAULT '',
    risk_tier TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','consumed','expired','invalidated')),
    reason TEXT,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    consumed_at TEXT,
    consumed_by TEXT,
    command_id TEXT,
    created_at TEXT NOT NULL DEFAULT ''
)
"""

GATEWAYS = """
CREATE TABLE IF NOT EXISTS device_gateways (
    gateway_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL CHECK(status IN ('enrollment_pending','trusted','online','degraded','offline','revoked')),
    protocol_version TEXT NOT NULL,
    adapter_inventory_json TEXT NOT NULL DEFAULT '[]',
    platform_json TEXT NOT NULL DEFAULT '{}',
    enrolled_at TEXT NOT NULL,
    activated_at TEXT,
    last_heartbeat_at TEXT,
    last_seen_version TEXT,
    revoked_at TEXT,
    revoke_reason TEXT
)
"""

GATEWAY_CREDENTIALS = """
CREATE TABLE IF NOT EXISTS gateway_credentials (
    credential_id TEXT PRIMARY KEY,
    gateway_id TEXT NOT NULL REFERENCES device_gateways(gateway_id),
    tenant_ref TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK(purpose IN ('enrollment','access')),
    credential_hash TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    rotated_from TEXT
)
"""

COMMANDS = """
CREATE TABLE IF NOT EXISTS device_commands (
    command_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    gateway_id TEXT NOT NULL,
    task_ref TEXT,
    run_ref TEXT,
    correlation_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    parameters_digest TEXT NOT NULL,
    intent TEXT NOT NULL,
    risk_tier TEXT NOT NULL DEFAULT 'write',
    deadline TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    approval_id TEXT,
    policy_version TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    state_hash TEXT,
    expected_state_json TEXT,
    status TEXT NOT NULL CHECK(status IN (
        'created','validated','authorized','queued','dispatched','received',
        'accepted','executing','verifying','succeeded','rejected','failed',
        'timed_out','cancelled','uncertain','expired')),
    status_reason TEXT,
    submitted_by TEXT NOT NULL,
    submitter_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    dispatched_at TEXT,
    completed_at TEXT,
    result_json TEXT,
    verification_json TEXT,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    protocol_version TEXT NOT NULL DEFAULT 'v1'
)
"""

TRANSITIONS = """
CREATE TABLE IF NOT EXISTS command_transitions (
    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id TEXT NOT NULL REFERENCES device_commands(command_id),
    tenant_ref TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    reason TEXT,
    actor_ref TEXT,
    actor_type TEXT,
    occurred_at TEXT NOT NULL
)
"""

OUTBOX = """
CREATE TABLE IF NOT EXISTS command_events (
    event_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_version TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    source_ref TEXT,
    correlation_id TEXT,
    task_ref TEXT,
    run_ref TEXT,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    published_at TEXT,
    delivery_attempts INTEGER NOT NULL DEFAULT 0
)
"""

AUDIT = """
CREATE TABLE IF NOT EXISTS audit_records (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_ref TEXT,
    actor_ref TEXT,
    actor_type TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    outcome TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    correlation_id TEXT,
    occurred_at TEXT NOT NULL
)
"""

MIGRATIONS: tuple[Migration, ...] = (    Migration(
        1,
        "baseline_reconcile_endpoints_leases_approvals",
        (
            ENDPOINTS,
            LEASES,
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_device_active_lease "
            "ON device_leases(endpoint_id) WHERE released_at IS NULL",
        ),
    ),
    Migration(
        2,
        "gateway_identity_and_credentials",
        (
            GATEWAYS,
            GATEWAY_CREDENTIALS,
            "CREATE INDEX IF NOT EXISTS ix_gateway_credentials_gateway "
            "ON gateway_credentials(gateway_id, purpose, revoked_at)",
            "CREATE INDEX IF NOT EXISTS ix_gateways_tenant ON device_gateways(tenant_ref, status)",
        ),
    ),
    Migration(
        3,
        "command_state_machine_outbox_audit",
        (
            COMMANDS,
            TRANSITIONS,
            OUTBOX,
            AUDIT,
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_command_idempotency "
            "ON device_commands(tenant_ref, endpoint_id, capability_id, idempotency_key)",
            "CREATE INDEX IF NOT EXISTS ix_commands_gateway_queue "
            "ON device_commands(gateway_id, status)",
            "CREATE INDEX IF NOT EXISTS ix_commands_tenant_endpoint "
            "ON device_commands(tenant_ref, endpoint_id, created_at)",
            "CREATE INDEX IF NOT EXISTS ix_events_tenant_time "
            "ON command_events(tenant_ref, occurred_at)",
            "CREATE INDEX IF NOT EXISTS ix_audit_tenant_time "
            "ON audit_records(tenant_ref, occurred_at)",
        ),
    ),
    Migration(
        4,
        "command_evidence_and_binding_columns",
        (
            "CREATE INDEX IF NOT EXISTS ix_approvals_pending "
            "ON device_approvals(tenant_ref, endpoint_id, status)",
            "CREATE INDEX IF NOT EXISTS ix_commands_status_deadline "
            "ON device_commands(status, deadline)",
        ),
    ),
    Migration(
        5,
        "dc006_manifest_device_binding_approval_v2",
        (
            "CREATE TABLE IF NOT EXISTS gateway_manifest_revisions ("
            " revision_id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " gateway_id TEXT NOT NULL, tenant_ref TEXT NOT NULL,"
            " manifest_version TEXT NOT NULL, digest TEXT NOT NULL,"
            " signature TEXT, manifest_json TEXT NOT NULL,"
            " registered_by TEXT, registered_at TEXT NOT NULL,"
            " UNIQUE(gateway_id, digest))",
            "CREATE INDEX IF NOT EXISTS ix_manifest_revisions_gateway "
            "ON gateway_manifest_revisions(tenant_ref, gateway_id, registered_at)",
        ),
    ),
    Migration(
        6,
        "dc007_evidence_metadata",
        (
            "CREATE TABLE IF NOT EXISTS device_evidence ("
            " evidence_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " gateway_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, device_id TEXT,"
            " command_id TEXT, task_ref TEXT, run_ref TEXT, correlation_id TEXT,"
            " evidence_type TEXT NOT NULL, mime_type TEXT NOT NULL,"
            " content_sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,"
            " captured_at TEXT NOT NULL, redaction_status TEXT NOT NULL,"
            " original_sha256 TEXT, redaction_processor TEXT, redaction_policy_version TEXT,"
            " redaction_key_id TEXT, redaction_proof TEXT, redaction_regions_json TEXT,"
            " retention_until TEXT, storage_ref TEXT NOT NULL,"
            " access_policy TEXT NOT NULL DEFAULT 'tenant_command_read',"
            " created_at TEXT NOT NULL, deleted_at TEXT,"
            " UNIQUE(storage_ref))",
            "CREATE INDEX IF NOT EXISTS ix_evidence_command "
            "ON device_evidence(tenant_ref, command_id, created_at)",
            "CREATE INDEX IF NOT EXISTS ix_evidence_retention "
            "ON device_evidence(retention_until, deleted_at)",
        ),
    ),
    Migration(
        7,
        "dc010_redaction_proof",
        (
            "CREATE INDEX IF NOT EXISTS ix_evidence_redaction "
            "ON device_evidence(tenant_ref, redaction_status)",
        ),
    ),
    Migration(
        8,
        "dc012_home_assistant_pilot",
        (            "CREATE TABLE IF NOT EXISTS platform_instances ("
            " platform_instance_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " adapter_id TEXT NOT NULL, base_url TEXT NOT NULL, secret_ref TEXT NOT NULL,"
            " platform_version TEXT, gateway_id TEXT NOT NULL, status TEXT NOT NULL,"
            " health_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,"
            " updated_at TEXT NOT NULL, UNIQUE(tenant_ref, base_url))",
            "CREATE TABLE IF NOT EXISTS iot_devices ("
            " device_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " platform_instance_id TEXT NOT NULL, native_platform TEXT NOT NULL,"
            " native_id TEXT NOT NULL, display_name TEXT NOT NULL, device_type TEXT NOT NULL,"
            " area TEXT, trust_state TEXT NOT NULL, connectivity_state TEXT NOT NULL,"
            " endpoint_id TEXT, capabilities_json TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}',"
            " created_at TEXT NOT NULL, updated_at TEXT NOT NULL,"
            " UNIQUE(tenant_ref, platform_instance_id, native_id))",
            "CREATE TABLE IF NOT EXISTS iot_twins ("
            " device_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " desired_json TEXT NOT NULL DEFAULT '{}', reported_json TEXT NOT NULL DEFAULT '{}',"
            " observed_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS ix_platform_instances_tenant "
            "ON platform_instances(tenant_ref, adapter_id)",
            "CREATE INDEX IF NOT EXISTS ix_iot_devices_tenant "
            "ON iot_devices(tenant_ref, trust_state, platform_instance_id)",
        ),
    ),
    Migration(
        9,
        "dc013_iot_telemetry",
        (
            "CREATE TABLE IF NOT EXISTS iot_telemetry ("
            " telemetry_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " platform_instance_id TEXT NOT NULL, device_id TEXT NOT NULL,"
            " entity_id TEXT, metric TEXT NOT NULL, value_json TEXT NOT NULL,"
            " unit TEXT, observed_at TEXT NOT NULL, received_at TEXT NOT NULL,"
            " source TEXT NOT NULL, quality TEXT NOT NULL, status TEXT NOT NULL,"
            " schema_version TEXT NOT NULL DEFAULT '1',"
            " UNIQUE(tenant_ref, device_id, metric, observed_at, source))",
            "CREATE INDEX IF NOT EXISTS ix_iot_telemetry_device_time "
            "ON iot_telemetry(tenant_ref, device_id, metric, observed_at)",
        ),
    ),
    Migration(
        10,
        "dc014_command_provider_status",
        (
            "ALTER TABLE device_commands ADD COLUMN provider_status TEXT",
            "CREATE INDEX IF NOT EXISTS ix_commands_canonical_review "
            "ON device_commands(tenant_ref, status, provider_status)",
        ),
    ),
    Migration(
        11,
        "dc014_ha_durable_event_ingestion",
        (
            "CREATE TABLE IF NOT EXISTS ha_event_log ("
            " event_key TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " platform_instance_id TEXT NOT NULL, device_id TEXT NOT NULL,"
            " entity_id TEXT NOT NULL, state TEXT, attributes_json TEXT NOT NULL DEFAULT '{}',"
            " attributes_hash TEXT NOT NULL, observed_at TEXT NOT NULL,"
            " received_at TEXT NOT NULL, context_id TEXT, quality TEXT NOT NULL,"
            " status TEXT NOT NULL, schema_version TEXT NOT NULL DEFAULT '1')",
            "CREATE INDEX IF NOT EXISTS ix_ha_event_log_device_time "
            "ON ha_event_log(tenant_ref, platform_instance_id, device_id, observed_at)",
            "CREATE TABLE IF NOT EXISTS ha_ingest_state ("
            " platform_instance_id TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL,"
            " connected INTEGER NOT NULL DEFAULT 0, last_event_at TEXT,"
            " last_event_key TEXT, last_received_at TEXT, last_reconcile_at TEXT,"
            " last_gap_at TEXT, reconnect_count INTEGER NOT NULL DEFAULT 0,"
            " duplicate_count INTEGER NOT NULL DEFAULT 0,"
            " gap_count INTEGER NOT NULL DEFAULT 0, last_error TEXT,"
            " updated_at TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS ix_ha_ingest_state_tenant "
            "ON ha_ingest_state(tenant_ref, platform_instance_id)",
        ),
    ),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def apply(connection: sqlite3.Connection) -> list[int]:
    """Apply all pending migrations and return the versions applied."""

    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
    newly_applied: list[int] = []
    for migration in MIGRATIONS:
        if migration.version in applied:
            continue
        connection.execute("BEGIN IMMEDIATE")
        try:
            already = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version=?", (migration.version,)
            ).fetchone()
            if already is not None:
                connection.execute("COMMIT")
                continue
            for statement in migration.statements:
                connection.execute(statement)
            if migration.version == 1:
                _adopt_legacy_endpoints(connection)
                _rebuild_approvals(connection)
            if migration.version == 5:
                _adopt_dc006(connection)
            if migration.version == 7:
                _adopt_dc010(connection)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (migration.version, migration.name, now_iso()),
            )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        newly_applied.append(migration.version)
    _ensure_indexes(connection)
    return newly_applied


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _adopt_legacy_endpoints(connection: sqlite3.Connection) -> None:
    existing = _columns(connection, "device_endpoints")
    additions = {
        "gateway_id": "TEXT",
        "credential_expires_at": "TEXT",
        "credential_rotated_at": "TEXT",
        "last_heartbeat_at": "TEXT",
        "revoke_reason": "TEXT",
        "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for column, definition in additions.items():
        if column not in existing:
            connection.execute(f"ALTER TABLE device_endpoints ADD COLUMN {column} {definition}")

    lease_columns = _columns(connection, "device_leases")
    for column, definition in {"holder_type": "TEXT", "released_reason": "TEXT"}.items():
        if column not in lease_columns:
            connection.execute(f"ALTER TABLE device_leases ADD COLUMN {column} {definition}")


def _rebuild_approvals(connection: sqlite3.Connection) -> None:
    existing = _columns(connection, "device_approvals")
    if not existing:
        connection.execute(APPROVALS_NEW)
        connection.execute("ALTER TABLE device_approvals_next RENAME TO device_approvals")
        return
    if {"gateway_id", "parameters_json", "policy_version"}.issubset(existing):
        return

    connection.execute("DROP TABLE IF EXISTS device_approvals_next")
    connection.execute(APPROVALS_NEW)
    legacy_rows = connection.execute("SELECT * FROM device_approvals").fetchall()
    columns = [row[1] for row in connection.execute("PRAGMA table_info(device_approvals)")]
    index = {name: position for position, name in enumerate(columns)}
    for row in legacy_rows:
        def value(name: str, default=None, _row=row):
            position = index.get(name)
            return _row[position] if position is not None else default

        status = value("status", "pending")
        if status not in {"pending", "approved", "denied", "consumed", "expired"}:
            status = "invalidated"
        connection.execute(
            "INSERT INTO device_approvals_next ("
            "approval_id, tenant_ref, endpoint_id, gateway_id, lease_id, requester_ref,"
            " requester_type, approver_ref, approver_type, action_digest, capability_id,"
            " capability_version, intent, parameters_json, state_hash, policy_version,"
            " risk_tier, status, reason, expires_at, decided_at, consumed_at, consumed_by,"
            " command_id, created_at)"
            " VALUES (?, ?, ?, '', ?, ?, 'agent', ?, NULL, ?, '', '', '', '{}', NULL, '',"
            " '', ?, NULL, ?, ?, NULL, NULL, NULL, '')",
            (
                value("approval_id"),
                value("tenant_ref"),
                value("endpoint_id"),
                value("lease_id"),
                value("requester_ref"),
                value("approver_ref"),
                value("action_digest"),
                status,
                value("expires_at"),
                value("decided_at"),
            ),
        )
    connection.execute("DROP TABLE device_approvals")
    connection.execute("ALTER TABLE device_approvals_next RENAME TO device_approvals")


def _adopt_dc006(connection: sqlite3.Connection) -> None:
    additions = {
        "device_endpoints": {
            "device_id": "TEXT",
            "device_fingerprint": "TEXT",
            "paired_at": "TEXT",
        },
        "device_gateways": {
            "endpoint_id": "TEXT",
            "device_id": "TEXT",
            "device_fingerprint": "TEXT",
            "manifest_version": "TEXT",
            "manifest_digest": "TEXT",
            "manifest_json": "TEXT",
            "manifest_updated_at": "TEXT",
            "reported_manifest_digest": "TEXT",
            "health_json": "TEXT NOT NULL DEFAULT '{}'",
            "queue_depth": "INTEGER",
            "queue_age_seconds": "REAL",
            "last_error": "TEXT",
        },
        "device_approvals": {
            "operation": "TEXT NOT NULL DEFAULT ''",
            "device_id": "TEXT",
            "device_fingerprint": "TEXT",
            "state_version": "TEXT",
            "manifest_digest": "TEXT NOT NULL DEFAULT ''",
            "approval_nonce": "TEXT NOT NULL DEFAULT ''",
        },
        "device_commands": {
            "operation": "TEXT NOT NULL DEFAULT ''",
            "device_id": "TEXT",
            "device_fingerprint": "TEXT",
            "state_version": "TEXT",
            "manifest_digest": "TEXT NOT NULL DEFAULT ''",
            "approval_nonce": "TEXT",
        },
    }
    for table, columns in additions.items():
        existing = _columns(connection, table)
        for column, definition in columns.items():
            if column not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_endpoint_device_id "
        "ON device_endpoints(tenant_ref, device_id) WHERE device_id IS NOT NULL"
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_endpoint_binding "
        "ON device_gateways(tenant_ref, endpoint_id) WHERE endpoint_id IS NOT NULL"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_endpoints_gateway_binding "
        "ON device_endpoints(tenant_ref, gateway_id, device_fingerprint)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_gateways_manifest "
        "ON device_gateways(tenant_ref, manifest_digest)"
    )


def _adopt_dc010(connection: sqlite3.Connection) -> None:
    existing = _columns(connection, "device_evidence")
    additions = {
        "original_sha256": "TEXT",
        "redaction_processor": "TEXT",
        "redaction_policy_version": "TEXT",
        "redaction_key_id": "TEXT",
        "redaction_proof": "TEXT",
        "redaction_regions_json": "TEXT",
    }
    for column, definition in additions.items():
        if column not in existing:
            connection.execute(f"ALTER TABLE device_evidence ADD COLUMN {column} {definition}")


def _ensure_indexes(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_endpoints_tenant ON device_endpoints(tenant_ref, status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS ix_leases_tenant ON device_leases(tenant_ref, endpoint_id)"
    )
    connection.commit()
