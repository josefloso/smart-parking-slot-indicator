import hashlib
import hmac
import itertools
import json
import subprocess
import time
from pathlib import Path

import paho.mqtt.client as mqtt
import pytest
import requests

HERE = Path(__file__).parent
REPO = HERE.parent.parent
RUN = HERE / ".run"
NODE_RED_URL = "http://localhost:18800"
MQTT_PORT = 18830
# Must match SMARTPARKING_HMAC_SECRET in docker-compose.yml (test value only).
TEST_SECRET = "integration-test-secret"
BOOT_ID = "1a2b3c4d"
_seq = itertools.count(1)


def signed_status(slot, state, distance=8.5, uptime=12000, key=TEST_SECRET, seq=None):
    """A status message signed the same way as the ESP32 firmware."""
    msg = {"slot": slot, "status": state, "distance_cm": distance, "uptime_ms": uptime,
           "boot": BOOT_ID, "seq": seq if seq is not None else next(_seq)}
    canonical = "|".join(str(v) for v in ("status", slot, state, f"{distance:.1f}", uptime, BOOT_ID, msg["seq"]))
    msg["sig"] = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return msg


def compose(*args, **kwargs):
    return subprocess.run(["docker", "compose", *args], cwd=HERE, check=True, **kwargs)


def sql(statement):
    """Run SQL inside the Node-RED container so SQLite locking is shared with Node-RED.
    .timeout makes the sqlite3 CLI wait for a lock held by Node-RED instead of failing at once."""
    result = compose("exec", "-T", "node-red", "sqlite3", "-json", "/db/parking.db",
                     input=".timeout 5000\n" + statement, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else []


def write_test_flows():
    """Same flow as production, pointed at the local broker and test database."""
    flows = json.loads((REPO / "node-red" / "flows.json").read_text())
    for node in flows:
        if node["type"] == "mqtt-broker":
            node["broker"] = "mosquitto"
            node["port"] = "1883"
            node["usetls"] = False  # the private test broker has no TLS
            node.pop("tls", None)
        if node["type"] == "sqlitedb":
            node["db"] = "/db/parking.db"
    (RUN / "flows.json").write_text(json.dumps(flows))


def wait_for(condition, timeout=30, message="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for {message}")


@pytest.fixture(scope="session")
def stack():
    RUN.mkdir(exist_ok=True)
    write_test_flows()

    compose("up", "-d", "--build")
    try:
        sql((REPO / "database" / "schema.sql").read_text())
        def node_red_up():
            try:
                return requests.get(f"{NODE_RED_URL}/dashboard/page1", timeout=2).status_code == 200
            except requests.ConnectionError:
                return False

        wait_for(node_red_up, timeout=90, message="Node-RED dashboard")
        yield
    finally:
        compose("logs", "node-red")
        compose("down", "-v")


@pytest.fixture(scope="session")
def broker(stack):
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    connected_clients = []
    client.on_message = lambda c, u, m: connected_clients.append(int(m.payload))
    client.connect("localhost", MQTT_PORT)
    client.subscribe("$SYS/broker/clients/connected")
    client.loop_start()
    # This client plus Node-RED must both be connected before publishing.
    wait_for(lambda: connected_clients and connected_clients[-1] >= 2, timeout=60, message="Node-RED MQTT connection")
    time.sleep(1)
    yield client
    client.loop_stop()
    client.disconnect()


@pytest.fixture
def db(stack):
    sql("DELETE FROM parking_logs; DELETE FROM security_events;")
    # Forget the flow's memory (last stored status, last sequence numbers) so each test starts clean.
    flow_tab = next(n["id"] for n in json.loads((RUN / "flows.json").read_text()) if n["type"] == "tab")
    for key in ("lastLogged", "lastSeq", "parkingStates"):
        response = requests.delete(f"{NODE_RED_URL}/context/flow/{flow_tab}/{key}", timeout=5)
        assert response.status_code in (204, 404), response.status_code
    return sql


@pytest.fixture
def publish(broker):
    def send(slot_topic, payload):
        body = payload if isinstance(payload, str) else json.dumps(payload)
        broker.publish(f"smartparking/slot{slot_topic}/status", body, qos=1).wait_for_publish()

    return send
