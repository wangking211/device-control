from device_control.iot.adapters.websocket import (
    Backoff,
    EventDeduper,
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
