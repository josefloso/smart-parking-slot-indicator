// Test tool for the Smart Parking system (Group 8).
// Acts as the ESP32 (signed messages over TLS), and can also act as an attacker
// to check that Node-RED rejects forged, modified and replayed messages.
//
//   npm run simulate                      demo: signed status changes for all slots
//   node --env-file=.env simulate_esp32.js 2 OCCUPIED      set one slot
//   node --env-file=.env simulate_esp32.js attack-unsigned  fake message, no signature
//   node --env-file=.env simulate_esp32.js attack-tampered  valid signature, changed status
//   node --env-file=.env simulate_esp32.js attack-replay    re-send an old signed message
//   node --env-file=.env simulate_esp32.js attack-wrongkey  signed with the wrong secret
const mqtt = require('mqtt');
const crypto = require('crypto');

const SECRET = process.env.SMARTPARKING_HMAC_SECRET;
if (!SECRET) {
  console.error('SMARTPARKING_HMAC_SECRET missing: run with node --env-file=.env');
  process.exit(1);
}

const bootId = crypto.randomBytes(4).toString('hex');
let seq = 0;
const start = Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hmac = (key, text) => crypto.createHmac('sha256', key).update(text).digest('hex');

function statusMessage(slot, status, key = SECRET) {
  const distance = status === 'OCCUPIED' ? 8 + Math.random() * 30 : 60 + Math.random() * 200;
  const d = {
    slot,
    status,
    distance_cm: Number(distance.toFixed(1)),
    uptime_ms: Date.now() - start,
    boot: bootId,
    seq: ++seq,
  };
  const canonical = ['status', slot, status, d.distance_cm.toFixed(1), d.uptime_ms, d.boot, d.seq].join('|');
  d.sig = hmac(key, canonical);
  return d;
}

const client = mqtt.connect('mqtts://broker.emqx.io:8883', {
  clientId: 'SmartParking-sim-' + crypto.randomBytes(3).toString('hex'),
  rejectUnauthorized: true, // verify the broker's TLS certificate
});

function send(slot, payload, retain = true) {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  client.publish(`smartparking/slot${slot}/status`, text, { retain, qos: 1 });
  console.log(`slot${slot} -> ${text.slice(0, 120)}${text.length > 120 ? '...' : ''}`);
}

client.on('connect', async () => {
  console.log('Connected to broker.emqx.io:8883 (TLS), boot', bootId);
  const [arg1, arg2] = process.argv.slice(2);

  if (arg1 === 'attack-unsigned') {
    // Old v1 format with no signature: anyone on the public broker could send this.
    send(1, { slot: 1, status: 'OCCUPIED', distance_cm: 5.0, uptime_ms: 1234 }, false);
  } else if (arg1 === 'attack-tampered') {
    const d = statusMessage(2, 'AVAILABLE');
    d.status = 'OCCUPIED'; // change the content after signing
    send(2, d, false);
  } else if (arg1 === 'attack-replay') {
    const original = statusMessage(3, 'OCCUPIED');
    send(3, original, false);       // genuine message: accepted
    await sleep(1500);
    send(3, original, false);       // identical copy re-sent: must be rejected
  } else if (arg1 === 'attack-wrongkey') {
    send(1, statusMessage(1, 'OCCUPIED', 'not-the-real-secret'), false);
  } else if (arg1) {
    send(Number(arg1), statusMessage(Number(arg1), (arg2 || 'OCCUPIED').toUpperCase()));
  } else {
    const steps = [
      [1, 'AVAILABLE'], [2, 'AVAILABLE'], [3, 'AVAILABLE'],
      [1, 'OCCUPIED'], [3, 'OCCUPIED'], [2, 'OCCUPIED'], // all full -> alert
      [2, 'OCCUPIED'],                                    // heartbeat repeat: not stored again
      [1, 'AVAILABLE'],
    ];
    for (const [slot, status] of steps) {
      send(slot, statusMessage(slot, status));
      await sleep(2000);
    }
  }
  await sleep(1000);
  client.end();
});

client.on('error', (e) => {
  console.error('MQTT error:', e.message);
  process.exit(1);
});
