"""Home Assistant WebSocket event client primitives.

The sync WebSocket transport is built on ``websockets.sync`` (available in the
pinned websockets version). It authenticates, subscribes to state_changed, and
reconnects with exponential backoff. Events are deduplicated by HA's context id
plus entity/state, and a reconnect triggers a REST reconciliation callback.

The adapter's synchronous `subscribe()` SPI remains an explicit gap marker until
this stream is wired into the event ingestion pipeline; it never pretends there
were no events when a cursor gap exists.
"""

from __future__ import annotations

import hashlib
import json
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass
class EventDeduper:
    capacity: int = 4096
    seen: set[str] = field(default_factory=set)
    order: list[str] = field(default_factory=list)
    duplicates: int = 0

    def accept(self, event: dict[str, Any]) -> bool:
        key = self._key(event)
        if key in self.seen:
            self.duplicates += 1
            return False
        self.seen.add(key)
        self.order.append(key)
        if len(self.order) > self.capacity:
            oldest = self.order.pop(0)
            self.seen.discard(oldest)
        return True

    @staticmethod
    def _key(event: dict[str, Any]) -> str:
        event_body = event.get("event") or {}
        context = event_body.get("context") or {}
        context_id = str(context.get("id") or "")
        data = event_body.get("data") or {}
        entity = str(data.get("entity_id") or "")
        new_state = data.get("new_state") or {}
        state = str(new_state.get("state") or "")
        # Attributes and last_updated are part of the identity: an
        # attribute-only change must not be deduplicated as the same event.
        attributes = new_state.get("attributes") or {}
        attributes_digest = hashlib.sha256(
            json.dumps(attributes, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")
        ).hexdigest()[:16]
        last_updated = str(new_state.get("last_updated") or "")
        if context_id:
            return f"{context_id}:{entity}:{state}:{attributes_digest}:{last_updated}"
        return (f"{event.get('time_fired')}:{entity}:{state}:{attributes_digest}:"
                f"{last_updated}:{event.get('event_type')}")


@dataclass
class Backoff:
    base_seconds: float = 0.5
    max_seconds: float = 30.0
    jitter: float = 0.2

    def delay(self, attempt: int, *, rng: Callable[[], float] | None = None) -> float:
        raw = min(self.max_seconds, self.base_seconds * (2 ** max(0, attempt)))
        noise = (rng or random.random)()
        return max(0.0, raw * (1 + self.jitter * (noise * 2 - 1)))


class EventCursorGap(RuntimeError):
    pass


def auth_messages() -> tuple[dict[str, Any], dict[str, Any]]:
    return ({"type": "auth_required"}, {"type": "auth"})


def classify_message(message: dict[str, Any]) -> str:
    if message.get("type") == "auth_required":
        return "auth_required"
    if message.get("type") == "auth_ok":
        return "auth_ok"
    if message.get("type") == "auth_invalid":
        return "auth_invalid"
    if message.get("type") == "event":
        return "event"
    return "other"


class HomeAssistantWebSocket:
    def __init__(self, *, base_url: str, token: str, ssl_context: ssl.SSLContext | None = None,
                 deduper: EventDeduper | None = None, backoff: Backoff | None = None,
                 reconnect_max: int = 10) -> None:
        base = base_url.rstrip("/")
        base = base.replace("https://", "wss://").replace("http://", "ws://")
        self.url = f"{base}/api/websocket"
        self.token = token
        self.ssl_context = ssl_context
        self.deduper = deduper or EventDeduper()
        self.backoff = backoff or Backoff()
        self.reconnect_max = reconnect_max
        self.last_event_at: float | None = None
        self.reconnects = 0
        self.last_gap: str | None = None

    def run(self, on_event: Callable[[dict[str, Any]], None],
            reconcile: Callable[[], None] | None = None,
            stop: Callable[[], bool] | None = None,
            max_events: int | None = None) -> int:
        """Blocking authenticated subscription; returns delivered event count."""

        from websockets.exceptions import ConnectionClosed
        from websockets.sync.client import connect as ws_connect

        delivered = 0
        attempt = 0
        while not (stop and stop()):
            try:
                with ws_connect(self.url, ssl=self.ssl_context, open_timeout=10) as ws:
                    hello = json.loads(ws.recv())
                    if classify_message(hello) != "auth_required":
                        raise ConnectionError("unexpected auth handshake")
                    ws.send(json.dumps({"type": "auth", "access_token": self.token}))
                    reply = json.loads(ws.recv())
                    if classify_message(reply) == "auth_invalid":
                        raise PermissionError("home_assistant_auth_invalid")
                    if classify_message(reply) != "auth_ok":
                        raise ConnectionError("unexpected auth result")
                    ws.send(json.dumps({
                        "id": 1, "type": "subscribe_events", "event_type": "state_changed",
                    }))
                    attempt = 0
                    while not (stop and stop()):
                        message = json.loads(ws.recv())
                        if classify_message(message) != "event":
                            continue
                        if not self.deduper.accept(message):
                            continue
                        self.last_event_at = time.time()
                        on_event(message)
                        delivered += 1
                        if max_events is not None and delivered >= max_events:
                            return delivered
            except PermissionError:
                # Invalid/revoked token is not transient; retrying cannot help.
                raise
            except (ConnectionClosed, ConnectionError, OSError):
                if reconcile is not None:
                    reconcile()
                if attempt >= self.reconnect_max:
                    self.last_gap = "reconnect_exhausted"
                    break
                time.sleep(self.backoff.delay(attempt))
                attempt += 1
                self.reconnects += 1
        return delivered


def event_entities(messages: Iterable[dict[str, Any]]) -> list[str]:
    entities = []
    for message in messages:
        data = (message.get("event") or {}).get("data") or {}
        entity = data.get("entity_id")
        if isinstance(entity, str):
            entities.append(entity)
    return entities
