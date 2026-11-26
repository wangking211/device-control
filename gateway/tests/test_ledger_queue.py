
import pytest
from device_gateway.ledger import CONFLICT, DUPLICATE, NEW, DedupeLedger
from device_gateway.queue import BackpressureError, BoundedQueue


def command(command_id="cmd-1", key="idem-1", app_id="com.example.notes"):
    return {
        "command_id": command_id,
        "idempotency_key": key,
        "capability_id": "app.launch",
        "capability_version": "1.0.0",
        "parameters": {"app_id": app_id},
        "intent": "open",
        "deadline": "2099-01-01T00:00:00+00:00",
        "state_hash": None,
    }


def test_ledger_dedupes_conflicts_and_survives_reopen(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = DedupeLedger(path)
    assert ledger.claim(command()).outcome == NEW
    assert ledger.claim(command()).outcome == DUPLICATE
    assert ledger.claim(command(app_id="com.example.other")).outcome == CONFLICT
    assert ledger.claim(command(command_id="cmd-2", key="idem-1")).outcome == CONFLICT
    ledger.complete("cmd-1", status="succeeded", result={"status": "succeeded"})
    ledger.close()

    reopened = DedupeLedger(path)
    claim = reopened.claim(command())
    assert claim.outcome == DUPLICATE
    assert claim.status == "succeeded"
    assert claim.result == {"status": "succeeded"}
    reopened.close()


def test_ledger_persists_pending_results_for_redelivery(tmp_path):
    ledger = DedupeLedger(tmp_path / "pending.sqlite3")
    ledger.claim(command())
    ledger.complete("cmd-1", status="result_pending", result={"status": "succeeded"})
    assert ledger.pending_results() == [("cmd-1", {"status": "succeeded"})]
    ledger.close()


def test_bounded_queue_rejects_when_full():
    queue = BoundedQueue(2)
    queue.put(command("cmd-1", "k1"))
    queue.put(command("cmd-2", "k2"))
    with pytest.raises(BackpressureError):
        queue.put(command("cmd-3", "k3"))
    assert len(queue) == 2
    assert queue.get_nowait()["command_id"] == "cmd-1"
    queue.put(command("cmd-3", "k3"))
    assert len(queue.drain()) == 2


def test_queue_rejects_invalid_capacity():
    with pytest.raises(ValueError):
        BoundedQueue(0)
