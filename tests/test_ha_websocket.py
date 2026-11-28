from device_control.iot.adapters.websocket import (
    Backoff,
    EventDeduper,
    HomeAssistantWebSocket,
    classify_message,
    event_entities,
)


def event(context="c1", entity="light.kitchen", state="on", event_type="state_changed"):
    return {
        "type": "event",
        "event_type": event_type,
        "time_fired": "2026-11-27T00:00:00+00:00",
        "event": {"context": {"id": context}, "data": {
            "entity_id": entity, "new_state": {"state": state},
        }},
    }


def test_event_deduper_uses_ha_context_and_bounds_memory():
    deduper = EventDeduper(capacity=2)
    assert deduper.accept(event("c1"))
    assert not deduper.accept(event("c1"))
    assert deduper.accept(event("c2"))
    assert deduper.accept(event("c3"))
    assert len(deduper.seen) == 2
    assert deduper.duplicates == 1
    assert event_entities([event("c4")]) == ["light.kitchen"]


def test_backoff_is_exponential_bounded_and_jittered():
    policy = Backoff(base_seconds=0.5, max_seconds=8.0, jitter=0.2)
    assert policy.delay(0, rng=lambda: 0.5) == 0.5
    assert policy.delay(1, rng=lambda: 0.5) == 1.0
    assert policy.delay(10, rng=lambda: 0.5) == 8.0
    low = policy.delay(2, rng=lambda: 0.0)
    high = policy.delay(2, rng=lambda: 1.0)
    assert low < high


def test_message_classification_and_auth_failure_boundary():
    assert classify_message({"type": "auth_required"}) == "auth_required"
    assert classify_message({"type": "auth_ok"}) == "auth_ok"
    assert classify_message({"type": "auth_invalid"}) == "auth_invalid"
    assert classify_message({"type": "event"}) == "event"
    assert classify_message({"type": "result"}) == "other"


class _Connection:
    def __init__(self, error=None):
        self.error = error
        self.calls = 0

    def close(self):
        self.calls += 1
        if self.error is not None:
            raise self.error


def _socket(connection):
    socket = HomeAssistantWebSocket(base_url="https://ha.example", token="token")
    socket._connection = connection
    return socket


def test_close_is_idempotent_and_records_no_error():
    connection = _Connection()
    socket = _socket(connection)
    socket.close()
    assert connection.calls == 1
    assert socket.last_close_error is None
    socket.close()
    assert connection.calls == 1


def test_close_tolerates_already_closed_transport():
    connection = _Connection(OSError("already closed"))
    socket = _socket(connection)
    socket.close()
    assert socket.last_close_error == "OSError"
    assert socket._connection is None


def test_close_records_unexpected_error_without_masking_caller():
    connection = _Connection(ValueError("unexpected"))
    socket = _socket(connection)
    socket.close()
    assert socket.last_close_error == "ValueError"
    assert socket._connection is None


def test_close_without_connection_is_a_noop():
    socket = _socket(None)
    socket.close()
    assert socket.last_close_error is None
