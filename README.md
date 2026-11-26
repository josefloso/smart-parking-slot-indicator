# Smart Parking Slot Indicator

An ESP32 system that shows which of three parking slots are free.

Each slot has an ultrasonic sensor. If something is closer than **50 cm** for three readings in a row (about 0.75 s), the slot is **occupied**: its red LED lights. Otherwise it is **available**: its green LED lights. An LCD shows the totals, and a web dashboard shows every slot live and stores the history for analysis.

```
3 x HC-SR04  ->  ESP32  --(Wi-Fi, MQTT over TLS, signed)-->  broker.emqx.io  -->  Node-RED  -->  SQLite
                 LEDs + LCD                                                           |
                                                                                      +-->  Dashboard
```

The project runs in the [Wokwi](https://wokwi.com) simulator, so no hardware is needed.

## Quick start

You need Node.js 20 or newer, and `sqlite3`.

**1. Create a shared secret.** The ESP32 signs every message with it and Node-RED checks the signature.

```sh
openssl rand -hex 32
cp sketch/secrets.example.h sketch/secrets.h     # paste the secret into HMAC_SECRET
cp node-red/.env.example node-red/.env           # paste the same secret, and choose the two passwords
```

**2. Create the database.**

```sh
cd node-red
sqlite3 parking.db < ../database/schema.sql
sqlite3 parking.db < ../database/seed.sql        # optional: sample data
```

**3. Start Node-RED.**

```sh
npm install
npm start
```

Open http://127.0.0.1:1880/dashboard and log in with the dashboard username and password from `node-red/.env`.

**4. Start the ESP32 in Wokwi.** Create an ESP32 project on wokwi.com and paste in `sketch/sketch.ino`, `sketch/diagram.json` and `sketch/libraries.txt`. Add a file tab called `secrets.h` with the contents of your `sketch/secrets.h`, then press **Start**. Keep the project private, because it holds the secret.

Click a sensor and drag its distance below 50 cm. The red LED lights, the LCD changes, and the dashboard shows the slot as occupied.

No Wokwi? Run `npm run simulate` in `node-red/` to send test messages instead.

## Project structure

| Folder | What is in it |
|---|---|
| `sketch/` | ESP32 firmware, Wokwi circuit, libraries, secret template |
| `node-red/` | Node-RED flow, secure settings, `.env` template, test and attack tool |
| `database/` | Database schema and sample data |
| `tests/` | Unit, integration and Wokwi tests |
| `docs/` | Full project report and system architecture design |

## How the pieces talk

The ESP32 publishes JSON messages over MQTT:

| Topic | Sent when | Example |
|---|---|---|
| `smartparking/slotN/status` | On every change, and every 10 s | `{"slot":1,"status":"OCCUPIED","distance_cm":8.5,"uptime_ms":12000,"boot":"3f19937d","seq":42,"sig":"..."}` |
| `smartparking/slotN/event` | On every change | `{"slot":1,"from":"AVAILABLE","to":"OCCUPIED",...}` |
| `smartparking/system/connection` | On connect, and on disconnect (Last Will) | `{"state":"ONLINE",...}` |
| `smartparking/command` | Sent to the ESP32 | `REFRESH` re-sends all statuses |

A slot's status is `AVAILABLE`, `OCCUPIED` or `SENSOR_ERROR` (the sensor stopped answering). Only real changes are stored in the database, not the 10-second repeats.

## Security

The broker is public, so anyone can connect to it. The system protects itself like this:

- **Encryption:** MQTT runs over TLS (port 8883), and the ESP32 checks the broker's certificate.
- **Signed messages:** every message carries an HMAC-SHA256 signature. Node-RED rejects messages that are unsigned, changed, or signed with the wrong key.
- **No replays:** every message has a sequence number, so an old message sent again is rejected.
- **Safe database writes:** values are checked and passed to SQL as parameters, never pasted into the query.
- **Logins:** the Node-RED editor and the dashboard need a password, and Node-RED only accepts connections from the same computer.
- **Audit:** rejected messages are counted on the dashboard and saved in the `security_events` table.

Secrets are never committed: `sketch/secrets.h` and `node-red/.env` are listed in `.gitignore`.

## Tests

| Test | Command |
|---|---|
| Database | `pytest tests/unit` |
| Node-RED functions | `node --test tests/unit/*.test.js` |
| Full system in Docker (broker, Node-RED, SQLite) | `pytest tests/integration` |
| Firmware in the Wokwi simulator | `arduino-cli compile --fqbn esp32:esp32:esp32 --output-dir sketch/build sketch`, then `wokwi-cli --scenario tests/wokwi/slot_detection.test.yaml sketch` |

Install the Python test tools first with `pip install -r tests/requirements.txt`. The Wokwi test needs a token from https://wokwi.com/dashboard/ci in `WOKWI_CLI_TOKEN`.

GitHub Actions runs all four on every push. To turn on the Wokwi test there, add `WOKWI_CLI_TOKEN` under **Settings > Secrets and variables > Actions**.

## Known limitations

- Anyone can still **read** messages on the public broker. Use a private broker with logins for a real car park.
- The secret is stored on the ESP32 as plain text. A real device should use flash encryption.
- Readings very close to 50 cm can make a slot switch back and forth.
- On real hardware, each sensor's ECHO pin needs a voltage divider (5 V to 3.3 V).
- Database times are in UTC. Use `datetime(timestamp, 'localtime')` to read them in local time.

## Documents

- [Full project report](docs/Smart%20Parking%20Slot%20Indicator%20-%20Group%208%20Report%20v2.docx): requirements, design, testing, analytics and security analysis
- [System architecture design](docs/System%20Architecture%20Design%20-%20Group%208.doc)
