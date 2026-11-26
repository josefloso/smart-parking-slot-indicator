-- Smart Parking Slot Indicator (Group 8) - database schema v2.0
-- All timestamps are stored in UTC. Read them in local time with
--   datetime(timestamp, 'localtime')

CREATE TABLE IF NOT EXISTS parking_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slot        INTEGER NOT NULL CHECK (slot BETWEEN 1 AND 99),
    status      TEXT    NOT NULL CHECK (status IN ('AVAILABLE', 'OCCUPIED', 'SENSOR_ERROR')),
    distance_cm REAL    CHECK (distance_cm BETWEEN -1 AND 500),
    uptime_ms   INTEGER CHECK (uptime_ms >= 0),
    boot_id     TEXT,                                -- device run that sent the message
    seq         INTEGER,                             -- message number within that run
    source      TEXT    NOT NULL DEFAULT 'live',     -- 'live' or imported test data
    timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_parking_logs_slot ON parking_logs (slot, id);

-- Node-RED already stores only status changes; this trigger is a second
-- safeguard so a repeated status for a slot is never stored twice.
CREATE TRIGGER IF NOT EXISTS prevent_consecutive_duplicate_status
BEFORE INSERT ON parking_logs
FOR EACH ROW
WHEN NEW.status = (
    SELECT status
    FROM parking_logs
    WHERE slot = NEW.slot
    ORDER BY id DESC
    LIMIT 1
)
BEGIN
    SELECT RAISE(IGNORE);
END;

-- Device online / offline events and other system events.
CREATE TABLE IF NOT EXISTS system_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event     TEXT NOT NULL,
    detail    TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Messages rejected by Node-RED's security checks (forged, modified, replayed, malformed).
CREATE TABLE IF NOT EXISTS security_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    reason    TEXT NOT NULL,
    topic     TEXT,
    payload   TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
