"""Verified platform principals for Device Control.

Claim conventions are taken from the actual ai-platform/MindOS implementation,
not invented:

* MindOS ``HmacBearerIdentityProvider`` (``products/mind-os/apps/api-gateway/
  app/core/identity_provider.py``) issues HS256 compact JWTs with ``sub``,
  ``tenant``, optional ``workspace``/``roles``/``permissions``/``iss``/``jti``.
* ``platform/packages/foundation-auth`` service tokens add an ``extra`` object
  with ``actor.actor_type == "service"``, ``tenant_id``, ``capability``,
  ``resource``, ``delegation_id`` and ``correlation_id``.

Device Control verifies the same wire format behind its own port so the
product can be deployed standalone. The verifier is deliberately small and
pins ``alg=HS256``; production configuration without a usable secret fails
closed instead of degrading to the bootstrap token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable

from device_control import config

MIN_SECRET_BYTES = 32
LEEWAY_SECONDS = 30
CLOCK_SKEW_ALLOWED = 5

# Scope catalogue.  ``*`` and ``device.*`` wildcards are honoured.
SCOPE_ENDPOINT_READ = "device.endpoint.read"
SCOPE_ENDPOINT_WRITE = "device.endpoint.write"
SCOPE_LEASE_ACQUIRE = "device.lease.acquire"
SCOPE_LEASE_RELEASE = "device.lease.release"
SCOPE_POLICY_EVALUATE = "device.policy.evaluate"
SCOPE_APPROVAL_REQUEST = "device.approval.request"
SCOPE_APPROVAL_DECIDE = "device.approval.decide"
SCOPE_COMMAND_SUBMIT = "device.command.submit"
SCOPE_COMMAND_READ = "device.command.read"
SCOPE_COMMAND_CANCEL = "device.command.cancel"
SCOPE_GATEWAY_READ = "device.gateway.read"
SCOPE_GATEWAY_WRITE = "device.gateway.write"
SCOPE_EVENT_READ = "device.event.read"
SCOPE_AUDIT_READ = "device.audit.read"

ALL_SCOPES = frozenset(
    {
        SCOPE_ENDPOINT_READ,
        SCOPE_ENDPOINT_WRITE,
        SCOPE_LEASE_ACQUIRE,
        SCOPE_LEASE_RELEASE,
        SCOPE_POLICY_EVALUATE,
        SCOPE_APPROVAL_REQUEST,
        SCOPE_APPROVAL_DECIDE,
        SCOPE_COMMAND_SUBMIT,
        SCOPE_COMMAND_READ,
        SCOPE_COMMAND_CANCEL,
        SCOPE_GATEWAY_READ,
        SCOPE_GATEWAY_WRITE,
        SCOPE_EVENT_READ,
        SCOPE_AUDIT_READ,
    }
)

ADMIN_ROLES = frozenset({"admin", "platform_admin", "device_admin", "superadmin"})


class IdentityUnavailable(RuntimeError):
    """The trusted identity dependency is not configured (fail closed)."""


class InvalidIdentity(ValueError):
    """The token is malformed, expired, forged or out of scope."""

    def __init__(self, code: str = "invalid_identity_token") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str | None
    principal_type: str
    scopes: frozenset[str]
    issuer: str | None = None
    credential_id: str = ""
    expires_at: int = 0
    roles: tuple[str, ...] = ()
    workspace: str | None = None
    resource_type: str = ""
    resource_id: str = ""
    correlation_id: str = ""
    bootstrap: bool = False

    @property
    def is_admin(self) -> bool:
        return "*" in self.scopes

    def has_scope(self, scope: str) -> bool:
        if "*" in self.scopes or scope in self.scopes:
            return True
        family = scope.rsplit(".", 1)[0]
        return f"{family}.*" in self.scopes

    def require_tenant(self) -> str:
        if not self.tenant:
            raise InvalidIdentity("tenant_missing_from_identity")
        return self.tenant


def bootstrap_principal() -> Principal:
    return Principal(
        subject="bootstrap-admin",
        tenant=None,
        principal_type="admin",
        scopes=frozenset({"*"}),
        issuer="local-bootstrap",
        credential_id="bootstrap",
        bootstrap=True,
    )


def verify_bearer(token: str) -> Principal:
    """Verify a platform bearer token and project it into a principal."""

    secret = config.identity_secret()
    if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
        raise IdentityUnavailable("MINDOS_IDENTITY_HMAC_KEY is not configured")

    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidIdentity("malformed_token")
    header = _decode_segment(parts[0])
    claims = _decode_segment(parts[1])
    if header.get("alg") != "HS256":
        raise InvalidIdentity("unsupported_token_algorithm")
    if header.get("typ", "JWT") != "JWT":
        raise InvalidIdentity("unsupported_token_type")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    provided = _b64url_decode(parts[2])
    if not hmac.compare_digest(expected, provided):
        raise InvalidIdentity("invalid_token_signature")

    now = time.time()
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp + LEEWAY_SECONDS < now:
        raise InvalidIdentity("expired_token")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and nbf - LEEWAY_SECONDS > now:
        raise InvalidIdentity("token_not_yet_valid")
    if str(claims.get("typ", "access")) != "access":
        raise InvalidIdentity("unsupported_token_type")

    expected_issuer = config.identity_issuer()
    if expected_issuer and claims.get("iss") != expected_issuer:
        raise InvalidIdentity("invalid_token_issuer")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise InvalidIdentity("subject_missing")
    extra_obj = claims.get("extra")
    extra: dict[str, Any] = extra_obj if isinstance(extra_obj, dict) else {}
    actor_obj = extra.get("actor")
    actor: dict[str, Any] = actor_obj if isinstance(actor_obj, dict) else {}
    is_service = actor.get("actor_type") == "service"
    if is_service:
        service_id = actor.get("service_id")
        if isinstance(service_id, str) and service_id and service_id != subject:
            raise InvalidIdentity("service_actor_mismatch")
        expected_audience = config.identity_audience()
        if expected_audience:
            audience = claims.get("aud")
            audiences = [audience] if isinstance(audience, str) else audience
            if not isinstance(audiences, list) or expected_audience not in audiences:
                raise InvalidIdentity("service_token_audience_mismatch")

    tenant = extra.get("tenant_id") if is_service else claims.get("tenant")
    if not isinstance(tenant, str) or not tenant.strip():
        raise InvalidIdentity("tenant_missing_from_identity")

    roles = _string_tuple(claims.get("roles") or claims.get("role"))
    permissions = _string_tuple(claims.get("permissions"))
    capability = extra.get("capability")
    scopes = _scopes_for(roles, permissions, capability, extra.get("scopes"))
    if not is_service and set(roles).isdisjoint(ADMIN_ROLES) and not scopes:
        # A verified user with no device scope is still a principal; the route
        # dependency rejects the specific operation with 403.
        scopes = frozenset()

    resource_obj = extra.get("resource")
    resource: dict[str, Any] = resource_obj if isinstance(resource_obj, dict) else {}
    principal_type = "service" if is_service else ("admin" if not set(roles).isdisjoint(ADMIN_ROLES) else "user")
    workspace = extra.get("workspace_id") if is_service else claims.get("workspace")
    return Principal(
        subject=subject,
        tenant=tenant.strip(),
        principal_type=principal_type,
        scopes=scopes,
        issuer=claims.get("iss") if isinstance(claims.get("iss"), str) else None,
        credential_id=str(claims.get("jti", "")),
        expires_at=int(exp),
        roles=roles,
        workspace=workspace if isinstance(workspace, str) else None,
        resource_type=str(resource.get("type") or ""),
        resource_id=str(resource.get("id") or ""),
        correlation_id=str(extra.get("correlation_id") or ""),
    )


def _scopes_for(
    roles: tuple[str, ...],
    permissions: tuple[str, ...],
    capability: Any,
    extra_scopes: Any,
) -> frozenset[str]:
    if not set(roles).isdisjoint(ADMIN_ROLES):
        return frozenset({"*"})
    scopes: set[str] = set(permissions)
    if isinstance(capability, str) and capability:
        scopes.add(capability)
    scopes.update(_string_tuple(extra_scopes))
    return frozenset(scopes)


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if isinstance(item, str) and item)
    return ()


def _b64url_decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode((segment + "=" * (-len(segment) % 4)).encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - normalize every base64 failure
        raise InvalidIdentity("malformed_token") from exc


def _decode_segment(segment: str) -> dict[str, Any]:
    try:
        value = json.loads(_b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidIdentity("malformed_token") from exc
    if not isinstance(value, dict):
        raise InvalidIdentity("malformed_token")
    return value


def scope_matches(granted: Iterable[str], required: str) -> bool:
    for scope in granted:
        if scope == "*" or scope == required:
            return True
        if scope.endswith(".*") and required.startswith(scope[:-1]):
            return True
    return False
