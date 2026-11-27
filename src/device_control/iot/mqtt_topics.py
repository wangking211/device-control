"""MQTT topic namespace and ACL helpers (no broker dependency).

Topic shape: ``dc/{tenant}/{device}/{endpoint}/{channel}[/{metric}]``.
Tenant wildcards are never allowed for clients. Commands must not be retained;
retained telemetry/state is allowed only with explicit policy. Payload limits and
QoS are enforced by the adapter/broker policy, not by this helper.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CHANNELS = {"telemetry", "event", "state", "command"}


class TopicError(ValueError):
    pass


def _segment(value: str, name: str) -> str:
    if not SAFE_SEGMENT.fullmatch(value) or value in {".", ".."}:
        raise TopicError(f"invalid topic segment: {name}")
    return value


def build_topic(*, tenant: str, device: str, endpoint: str, channel: str,
                metric: str | None = None) -> str:
    if channel not in CHANNELS:
        raise TopicError("invalid channel")
    parts = ["dc", _segment(tenant, "tenant"), _segment(device, "device"),
             _segment(endpoint, "endpoint"), channel]
    if metric:
        parts.append(_segment(metric, "metric"))
    return "/".join(parts)


def parse_topic(topic: str) -> dict[str, str | None]:
    parts = topic.split("/")
    if len(parts) not in {5, 6} or parts[0] != "dc" or parts[4] not in CHANNELS:
        raise TopicError("invalid topic")
    return {
        "tenant": parts[1], "device": parts[2], "endpoint": parts[3],
        "channel": parts[4], "metric": parts[5] if len(parts) == 6 else None,
    }


@dataclass(frozen=True)
class AclRule:
    tenant: str
    device: str | None = None
    endpoint: str | None = None
    channels: frozenset[str] = frozenset({"telemetry", "state", "event"})
    subscribe: bool = True
    publish: bool = False

    def allows(self, topic: str, *, action: str) -> bool:
        parsed = parse_topic(topic)
        if parsed["tenant"] != self.tenant:
            return False
        if self.device and parsed["device"] != self.device:
            return False
        if self.endpoint and parsed["endpoint"] != self.endpoint:
            return False
        if parsed["channel"] not in self.channels:
            return False
        if action == "subscribe":
            return self.subscribe
        if action == "publish":
            return self.publish
        return False


def validate_retained(channel: str, *, retained: bool) -> bool:
    if channel == "command" and retained:
        raise TopicError("retained command is forbidden")
    return retained
