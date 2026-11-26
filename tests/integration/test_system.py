"""System integration tests: MQTT -> Node-RED (security gate) -> SQLite, plus the dashboard."""
import requests

from conftest import NODE_RED_URL, signed_status, wait_for


def rows(db):
    result = db("SELECT slot, status, distance_cm, uptime_ms FROM parking_logs ORDER BY id;")
    return [(r["slot"], r["status"], r["distance_cm"], r["uptime_ms"]) for r in result]


def wait_for_rows(db, count):
    try:
        wait_for(lambda: len(rows(db)) == count, timeout=10, message=f"{count} rows")
    except TimeoutError:
        raise AssertionError(f"expected {count} rows, got {rows(db)}")
    return rows(db)


def security_reasons(db):
    return [r["reason"] for r in db("SELECT reason FROM security_events ORDER BY id;")]


def test_dashboard_page_is_served(stack):
    response = requests.get(f"{NODE_RED_URL}/dashboard/page1", timeout=5)
    assert response.status_code == 200


def test_signed_status_message_is_stored(db, publish):
    publish(1, signed_status(1, "OCCUPIED", 8.5, 12000))

    assert wait_for_rows(db, 1) == [(1, "OCCUPIED", 8.5, 12000)]
    [row] = db("SELECT timestamp, boot_id, seq FROM parking_logs;")
    assert row["timestamp"] and row["boot_id"] == "1a2b3c4d" and row["seq"]


def test_heartbeat_repeats_are_not_stored(db, publish):
    for uptime in (10000, 20000, 30000):
        publish(2, signed_status(2, "AVAILABLE", 28.1, uptime))
    publish(2, signed_status(2, "OCCUPIED", 6.0, 40000))

    assert wait_for_rows(db, 2) == [(2, "AVAILABLE", 28.1, 10000), (2, "OCCUPIED", 6.0, 40000)]


def test_each_slot_is_logged_independently(db, publish):
    for slot in (1, 2, 3):
        publish(slot, signed_status(slot, "AVAILABLE", 30.0, slot))

    assert sorted(wait_for_rows(db, 3)) == [(1, "AVAILABLE", 30.0, 1), (2, "AVAILABLE", 30.0, 2), (3, "AVAILABLE", 30.0, 3)]


def test_sensor_fault_is_stored(db, publish):
    publish(1, signed_status(1, "SENSOR_ERROR", -1.0, 7000))

    assert wait_for_rows(db, 1) == [(1, "SENSOR_ERROR", -1.0, 7000)]


def test_forged_modified_replayed_and_malformed_messages_are_rejected(db, publish):
    tampered = signed_status(3, "AVAILABLE", 99.0, 1)
    tampered["status"] = "OCCUPIED"
    injected = signed_status(3, "OCCUPIED")
    injected["status"] = "OCCUPIED'); DROP TABLE parking_logs; --"
    genuine = signed_status(3, "OCCUPIED", 7.0, 2)

    publish(3, {"slot": 3, "status": "OCCUPIED", "distance_cm": 5.0, "uptime_ms": 1})  # unsigned (v1 format)
    publish(3, tampered)                                                            # changed after signing
    publish(3, signed_status(3, "OCCUPIED", key="wrong-key"))                      # wrong secret
    publish(3, injected)                                                            # SQL injection attempt
    publish(3, "not json")
    publish(3, genuine)                                                             # accepted
    publish(3, genuine)                                                             # exact replay
    # Messages on one topic are delivered in order, so once this arrives the rest were handled.
    publish(3, signed_status(3, "AVAILABLE", 99.0, 5))

    assert wait_for_rows(db, 2) == [(3, "OCCUPIED", 7.0, 2), (3, "AVAILABLE", 99.0, 5)]
    # The security log is rate-limited (5 per second), so check it recorded rejections, not an exact count.
    wait_for(lambda: len(security_reasons(db)) >= 1, timeout=10, message="security events")
    assert db("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'parking_logs';")[0]["n"] == 1
