"""Unit tests for database/schema.sql and database/seed.sql."""
import sqlite3
from pathlib import Path

import pytest

DATABASE = Path(__file__).parent.parent.parent / "database"


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.executescript((DATABASE / "schema.sql").read_text())
    yield conn
    conn.close()


def insert(db, slot, status):
    db.execute("INSERT INTO parking_logs (slot, status, distance_cm, uptime_ms) VALUES (?, ?, 10.0, 1000)", (slot, status))


def statuses(db):
    return db.execute("SELECT slot, status FROM parking_logs ORDER BY id").fetchall()


def test_repeated_status_for_a_slot_is_ignored(db):
    insert(db, 1, "OCCUPIED")
    insert(db, 1, "OCCUPIED")
    assert statuses(db) == [(1, "OCCUPIED")]


def test_status_change_is_stored(db):
    insert(db, 1, "OCCUPIED")
    insert(db, 1, "AVAILABLE")
    insert(db, 1, "OCCUPIED")
    assert statuses(db) == [(1, "OCCUPIED"), (1, "AVAILABLE"), (1, "OCCUPIED")]


def test_slots_are_independent(db):
    insert(db, 1, "OCCUPIED")
    insert(db, 2, "OCCUPIED")
    insert(db, 3, "OCCUPIED")
    assert len(statuses(db)) == 3


def test_timestamp_defaults_to_insert_time(db):
    insert(db, 1, "OCCUPIED")
    [(timestamp,)] = db.execute("SELECT timestamp FROM parking_logs").fetchall()
    assert len(timestamp) == 19  # YYYY-MM-DD HH:MM:SS


def test_seed_data_loads_without_test_rows_or_duplicates(db):
    db.executescript((DATABASE / "seed.sql").read_text())
    rows = db.execute("SELECT id, slot, status FROM parking_logs ORDER BY id").fetchall()
    assert len(rows) == 48
    assert 6 not in [r[0] for r in rows]
    last = {}
    for _, slot, status in rows:
        assert last.get(slot) != status
        last[slot] = status


def test_latest_status_query_from_report(db):
    db.executescript((DATABASE / "seed.sql").read_text())
    latest = db.execute("""
        SELECT p.slot, p.status FROM parking_logs AS p
        WHERE p.id = (SELECT MAX(p2.id) FROM parking_logs AS p2 WHERE p2.slot = p.slot)
        ORDER BY p.slot
    """).fetchall()
    assert latest == [(1, "AVAILABLE"), (2, "AVAILABLE"), (3, "OCCUPIED")]


@pytest.mark.parametrize("slot, status", [(1, "UNKNOWN"), (1, "occupied"), (0, "OCCUPIED"), (100, "OCCUPIED")])
def test_invalid_rows_are_refused_by_check_constraints(db, slot, status):
    with pytest.raises(sqlite3.IntegrityError):
        insert(db, slot, status)


def test_sensor_error_is_stored(db):
    db.execute("INSERT INTO parking_logs (slot, status, distance_cm, uptime_ms) VALUES (2, 'SENSOR_ERROR', -1.0, 5000)")
    assert statuses(db) == [(2, "SENSOR_ERROR")]


def test_timestamp_is_utc(db):
    insert(db, 1, "OCCUPIED")
    [(age_seconds,)] = db.execute(
        "SELECT ABS(strftime('%s', 'now') - strftime('%s', timestamp)) FROM parking_logs").fetchall()
    assert age_seconds < 5


def test_seed_data_is_marked_as_legacy_and_in_utc(db):
    db.executescript((DATABASE / "seed.sql").read_text())
    sources = {s for (s,) in db.execute("SELECT DISTINCT source FROM parking_logs")}
    assert sources == {"legacy-2026-11-21-test-session"}
    [(first,)] = db.execute("SELECT timestamp FROM parking_logs WHERE id = 7").fetchall()
    assert first == "2026-11-21 05:55:50"  # 08:55:50 at UTC+3


def test_event_tables_exist(db):
    db.execute("INSERT INTO system_events (event, detail) VALUES ('DEVICE_ONLINE', 'boot 3f19937d, seq 1')")
    db.execute("INSERT INTO security_events (reason, topic, payload) VALUES ('signature check failed', 'smartparking/slot1/status', '{}')")
    assert db.execute("SELECT COUNT(*) FROM system_events").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 1
