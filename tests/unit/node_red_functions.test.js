// Unit tests for the JavaScript inside the Node-RED function nodes (flow v2.0).
// Run with: node --test tests/unit
const { test } = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const path = require("node:path");

const flows = require(path.join(__dirname, "..", "..", "node-red", "flows.json"));
const byName = (name) => flows.find((n) => n.name === name);
const SECRET = "unit-test-secret";

// Runs a function node's code the way Node-RED does, with fake flow/env/node objects.
function makeFunction(name, store = {}) {
  const def = byName(name);
  assert.ok(def, `function node "${name}" not found`);
  const flow = { get: (k) => store[k], set: (k, v) => { store[k] = v; } };
  const env = { get: (k) => ({ SMARTPARKING_HMAC_SECRET: SECRET, SLOT_COUNT: "3" })[k] };
  const node = { warn() {}, error() {}, status() {}, outputCount: def.outputs };
  const fn = new Function("msg", "flow", "env", "node", "crypto", def.func);
  return (msg) => fn(structuredClone(msg), flow, env, node, crypto);
}

// Builds a status message signed exactly like the ESP32 firmware does.
let seq = 0;
function signedStatus(slot, status, { distance = 8.5, uptime = 12000, boot = "3f19937d", key = SECRET, n } = {}) {
  const d = { slot, status, distance_cm: distance, uptime_ms: uptime, boot, seq: n ?? ++seq };
  const canonical = ["status", slot, status, distance.toFixed(1), uptime, boot, d.seq].join("|");
  d.sig = crypto.createHmac("sha256", key).update(canonical).digest("hex");
  return d;
}
const mqttMsg = (slot, payload, extra = {}) =>
  ({ topic: `smartparking/slot${slot}/status`, payload: typeof payload === "string" ? payload : JSON.stringify(payload), ...extra });
const outputIndex = (result) => (result ? result.findIndex((m) => m) : -1);

// ---------------------------------------------------------------- security gate
const VERIFY = "Verify signature, replay & schema";

test("Verify accepts a correctly signed status and strips the signature", () => {
  const verify = makeFunction(VERIFY);
  const out = verify(mqttMsg(2, signedStatus(2, "OCCUPIED", { distance: 6.04 })));
  assert.strictEqual(outputIndex(out), 0);
  assert.strictEqual(out[0].payload.status, "OCCUPIED");
  assert.strictEqual(out[0].payload.sig, undefined);
});

test("Verify rejects forged, modified and malformed messages", () => {
  const tampered = signedStatus(1, "AVAILABLE");
  tampered.status = "OCCUPIED";
  const injected = signedStatus(1, "OCCUPIED");
  injected.status = "OCCUPIED'); DROP TABLE parking_logs; --";
  const cases = {
    "unsigned v1 message": mqttMsg(1, { slot: 1, status: "OCCUPIED", distance_cm: 5, uptime_ms: 1 }),
    "status changed after signing": mqttMsg(1, tampered),
    "signed with the wrong key": mqttMsg(1, signedStatus(1, "OCCUPIED", { key: "wrong" })),
    "SQL injection in status": mqttMsg(1, injected),
    "not JSON": mqttMsg(1, "not json"),
    "slot does not match topic": mqttMsg(1, signedStatus(2, "OCCUPIED")),
    "slot out of range": mqttMsg(4, signedStatus(4, "OCCUPIED")),
    "distance out of range": mqttMsg(1, signedStatus(1, "OCCUPIED", { distance: 900 })),
  };
  for (const [label, msg] of Object.entries(cases)) {
    const out = makeFunction(VERIFY)(msg);
    assert.strictEqual(outputIndex(out), 3, label);
    assert.ok(out[3].payload.reason, label);
  }
});

test("Verify rejects a replayed message but silently ignores a retained copy", () => {
  const verify = makeFunction(VERIFY);
  const original = signedStatus(3, "OCCUPIED");
  assert.strictEqual(outputIndex(verify(mqttMsg(3, original))), 0);
  assert.strictEqual(verify(mqttMsg(3, original, { retain: true })), null);
  const replay = verify(mqttMsg(3, original));
  assert.strictEqual(outputIndex(replay), 3);
  assert.match(replay[3].payload.reason, /replay/);
});

test("Verify routes signed connection and event messages", () => {
  const verify = makeFunction(VERIFY);
  const conn = { state: "ONLINE", boot: "3f19937d", seq: 1 };
  conn.sig = crypto.createHmac("sha256", SECRET).update(["conn", "ONLINE", conn.boot, 1].join("|")).digest("hex");
  assert.strictEqual(outputIndex(verify({ topic: "smartparking/system/connection", payload: JSON.stringify(conn) })), 2);

  const ev = { slot: 1, from: "AVAILABLE", to: "OCCUPIED", distance_cm: 8, uptime_ms: 5, boot: "3f19937d", seq: 2 };
  ev.sig = crypto.createHmac("sha256", SECRET)
    .update(["event", 1, "AVAILABLE", "OCCUPIED", "8.0", 5, ev.boot, 2].join("|")).digest("hex");
  assert.strictEqual(outputIndex(verify({ topic: "smartparking/slot1/event", payload: JSON.stringify(ev) })), 1);
});

test("Verify rejects the old plain-text ONLINE connection message", () => {
  const out = makeFunction(VERIFY)({ topic: "smartparking/system/connection", payload: "ONLINE" });
  assert.strictEqual(outputIndex(out), 3);
});

// ---------------------------------------------------------------- storage
const STORE = "Store state change (parameterised)";
const verified = (slot, status, distance = 8.5) =>
  ({ payload: { slot, status, distance_cm: distance, uptime_ms: 12000, boot: "3f19937d", seq: 1 } });

test("Store builds a parameterised insert with no values in the SQL text", () => {
  const msg = makeFunction(STORE)(verified(2, "OCCUPIED", 6.04));
  assert.match(msg.topic, /^INSERT INTO parking_logs/);
  assert.doesNotMatch(msg.topic, /OCCUPIED|6\.04/);
  assert.strictEqual(msg.topic.split("$").length - 1, msg.payload.length);
  assert.deepStrictEqual(msg.payload.slice(0, 3), [2, "OCCUPIED", 6.04]);
});

test("Store skips repeated statuses and UNKNOWN, but stores changes and sensor faults", () => {
  const store = makeFunction(STORE);
  assert.ok(store(verified(1, "AVAILABLE")));
  assert.strictEqual(store(verified(1, "AVAILABLE", 30)), null);
  assert.strictEqual(store(verified(1, "UNKNOWN")), null);
  assert.ok(store(verified(2, "AVAILABLE")));
  assert.ok(store(verified(1, "OCCUPIED")));
  assert.ok(store(verified(1, "SENSOR_ERROR", -1)));
});

// ---------------------------------------------------------------- dashboard
test("Parking summary counts slots, rate and alerts", () => {
  const summary = makeFunction("Parking summary");
  summary(verified(1, "OCCUPIED"));
  let [overview, available, occupied, rate, alert] = summary(verified(2, "AVAILABLE"));
  assert.strictEqual(available.payload, 1);
  assert.strictEqual(occupied.payload, 1);
  assert.strictEqual(rate.payload, "33.3 %");
  assert.match(overview.payload, /Unknown 1/);
  assert.strictEqual(alert.payload, "No alerts");

  summary(verified(2, "OCCUPIED"));
  [, , occupied, rate, alert] = summary(verified(3, "OCCUPIED"));
  assert.strictEqual(occupied.payload, 3);
  assert.strictEqual(rate.payload, "100 %");
  assert.match(alert.payload, /All parking slots occupied/);

  [, , , , alert] = summary(verified(3, "SENSOR_ERROR", -1));
  assert.match(alert.payload, /sensor fault/);
});

test("Slot status goes to the right widget with the right colour", () => {
  const show = makeFunction("Show slot status");
  const colours = { AVAILABLE: "#2e7d32", OCCUPIED: "#e53935", SENSOR_ERROR: "#ef6c00" };
  for (const slot of [1, 2, 3]) {
    for (const [status, colour] of Object.entries(colours)) {
      const out = show(verified(slot, status, status === "SENSOR_ERROR" ? -1 : 8.5));
      assert.strictEqual(outputIndex(out), slot - 1);
      assert.strictEqual(out[slot - 1].ui_update.color, colour);
    }
  }
});

test("Security events are counted and stored with a parameterised query", () => {
  const record = makeFunction("Record security event");
  record({ payload: { reason: "signature check failed", topic: "smartparking/slot1/status", raw: "{}" } });
  const [count, , insert] = record({ payload: { reason: "replay", topic: "smartparking/slot1/status", raw: "{}" } });
  assert.strictEqual(count.payload, 2);
  assert.strictEqual(insert.topic.split("$").length - 1, insert.payload.length);
});

// ---------------------------------------------------------------- configuration
test("Flow subscribes only to the project's three topic patterns", () => {
  const topics = flows.filter((n) => n.type === "mqtt in").map((n) => n.topic).sort();
  assert.deepStrictEqual(topics, ["smartparking/+/event", "smartparking/+/status", "smartparking/system/connection"]);
});

test("Broker uses TLS on port 8883 with certificate checks and a clean host name", () => {
  const broker = flows.find((n) => n.type === "mqtt-broker");
  assert.strictEqual(broker.broker, broker.broker.trim(), "hidden whitespace in broker address");
  assert.strictEqual(broker.broker, "broker.emqx.io");
  assert.strictEqual(Number(broker.port), 8883);
  assert.strictEqual(broker.usetls, true);
  assert.strictEqual(broker.clientid, "", "fixed client IDs clash between teammates");
  assert.strictEqual(flows.find((n) => n.id === broker.tls).verifyservercert, true);
});

test("No secrets are stored in the flow", () => {
  const text = JSON.stringify(flows);
  assert.doesNotMatch(text, /[0-9a-f]{64}/, "looks like a hard-coded HMAC secret");
});

test("Database path is not tied to one computer", () => {
  const db = flows.find((n) => n.type === "sqlitedb").db;
  assert.ok(!/^[A-Za-z]:\\|^\//.test(db), db);
});
