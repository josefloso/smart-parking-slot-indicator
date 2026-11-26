/*
  IoT Smart Parking Slot Indicator - Group 8 - firmware v2.0
  ------------------------------------------------------------
  Board      : ESP32 DevKit V1 (Wokwi part: wokwi-esp32-devkit-v1)
  Sensors    : 3 x HC-SR04 ultrasonic (one per slot)
  Indicators : 3 green + 3 red LEDs, 16x2 I2C LCD (free / occupied count)
  Network    : Wi-Fi + MQTT over TLS (port 8883) to broker.emqx.io

  Slot rule  : distance <  50 cm for 3 readings in a row -> OCCUPIED  (red LED)
               distance >= 50 cm for 3 readings in a row -> AVAILABLE (green LED)
               no echo for 3 readings in a row           -> SENSOR_ERROR (both LEDs off)
               before the first confirmed reading         -> UNKNOWN (both LEDs off)

  Security (v2.0):
    - TLS encrypts all MQTT traffic and checks the broker's certificate.
    - Every message is signed with HMAC-SHA256 using a shared secret. Node-RED
      rejects messages with a missing or wrong signature (spoofing/tampering).
    - Every message carries a boot ID and a sequence number. Node-RED rejects
      old sequence numbers (replay).
    - The command topic is rate-limited to one refresh per 5 seconds.

  Physical hardware warning:
    HC-SR04 ECHO is 5 V and ESP32 GPIO is NOT 5 V tolerant. Use a voltage
    divider (e.g. 1 kOhm / 2 kOhm) on every ECHO line. Power HC-SR04 and the
    LCD backpack from 5 V and share GND.
*/

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include "mbedtls/md.h"

// -------------------- Network configuration --------------------
const char* WIFI_SSID     = "Wokwi-GUEST";
const char* WIFI_PASSWORD = "";

const char*    MQTT_HOST = "broker.emqx.io";
const uint16_t MQTT_PORT = 8883;  // MQTT over TLS

const char* TOPIC_COMMAND    = "smartparking/command";
const char* TOPIC_CONNECTION = "smartparking/system/connection";

// The shared HMAC secret lives in secrets.h, which is never committed to git.
// Copy secrets.example.h to secrets.h and set HMAC_SECRET to the same value as
// SMARTPARKING_HMAC_SECRET in Node-RED's .env file. In Wokwi, add secrets.h as a
// new file tab. On a real device, store the secret in encrypted flash (NVS with
// flash encryption) instead, and keep the Wokwi project private.
#include "secrets.h"

// Root certificate that signs broker.emqx.io (DigiCert Global Root G2, valid to 2038).
const char* ROOT_CA = R"PEM(
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
)PEM";

WiFiClientSecure netClient;
PubSubClient mqtt(netClient);

// -------------------- Hardware configuration --------------------
const uint8_t SLOT_COUNT = 3;

const uint8_t trigPins[SLOT_COUNT]  = {5, 22, 27};
const uint8_t echoPins[SLOT_COUNT]  = {18, 23, 32};
const uint8_t greenPins[SLOT_COUNT] = {19, 25, 16};
const uint8_t redPins[SLOT_COUNT]   = {21, 26, 17};

const uint8_t LCD_SDA = 4;
const uint8_t LCD_SCL = 13;
const uint8_t LCD_ADDRESS = 0x27;
LiquidCrystal_I2C lcd(LCD_ADDRESS, 16, 2);

// -------------------- Detection configuration --------------------
const float OCCUPIED_THRESHOLD_CM = 50.0;
const uint8_t CONFIRMATION_READINGS = 3;
const uint8_t SENSOR_ERROR_READINGS = 3;
const unsigned long SENSOR_INTERVAL_MS     = 250;
const unsigned long HEARTBEAT_INTERVAL_MS  = 10000;
const unsigned long WIFI_RETRY_INTERVAL_MS = 5000;
const unsigned long MQTT_RETRY_INTERVAL_MS = 5000;
const unsigned long COMMAND_MIN_GAP_MS     = 5000;
const unsigned long LCD_REFRESH_MS         = 1000;
const unsigned long ECHO_TIMEOUT_US        = 25000;  // ~4.3 m maximum range

// -------------------- Slot state --------------------
enum SlotState { UNKNOWN, AVAILABLE, OCCUPIED, SENSOR_ERROR };

SlotState slotState[SLOT_COUNT] = {UNKNOWN, UNKNOWN, UNKNOWN};
uint8_t occupiedStreak[SLOT_COUNT]  = {0, 0, 0};
uint8_t availableStreak[SLOT_COUNT] = {0, 0, 0};
uint8_t errorStreak[SLOT_COUNT]     = {0, 0, 0};
uint8_t validStreak[SLOT_COUNT]     = {0, 0, 0};
float lastDistanceCm[SLOT_COUNT]    = {-1, -1, -1};

unsigned long lastSensorScan = 0;
unsigned long lastHeartbeat = 0;
unsigned long lastWifiAttempt = 0;
unsigned long lastMqttAttempt = 0;
unsigned long lastCommandAt = 0;
unsigned long lastLcdUpdate = 0;
bool wifiWasConnected = false;
bool lcdDirty = true;

String mqttClientId;
char bootId[9];          // random 32-bit ID, new on every boot
uint32_t messageSeq = 0; // increases with every signed message
char willPayload[200];   // signed OFFLINE message, kept alive for the MQTT session

// -------------------- Helper functions --------------------
const char* stateName(SlotState state) {
  switch (state) {
    case AVAILABLE:    return "AVAILABLE";
    case OCCUPIED:     return "OCCUPIED";
    case SENSOR_ERROR: return "SENSOR_ERROR";
    default:           return "UNKNOWN";
  }
}

char stateLetter(SlotState state) {
  switch (state) {
    case AVAILABLE:    return 'F';  // free
    case OCCUPIED:     return 'O';
    case SENSOR_ERROR: return 'E';
    default:           return '?';
  }
}

// HMAC-SHA256 of `message`, written as 64 lowercase hex characters.
void signMessage(const char* message, char out[65]) {
  uint8_t mac[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const unsigned char*)HMAC_SECRET, strlen(HMAC_SECRET),
                  (const unsigned char*)message, strlen(message), mac);
  for (int i = 0; i < 32; i++) {
    snprintf(out + 2 * i, 3, "%02x", mac[i]);
  }
  out[64] = '\0';
}

// Builds a signed connection message ("ONLINE" or "OFFLINE").
void buildConnectionPayload(const char* state, char* out, size_t outSize) {
  uint32_t seq = ++messageSeq;
  char canonical[80];
  snprintf(canonical, sizeof(canonical), "conn|%s|%s|%lu",
           state, bootId, (unsigned long)seq);
  char sig[65];
  signMessage(canonical, sig);
  snprintf(out, outSize,
           "{\"state\":\"%s\",\"boot\":\"%s\",\"seq\":%lu,\"sig\":\"%s\"}",
           state, bootId, (unsigned long)seq, sig);
}

void setIndicators(uint8_t slot) {
  // UNKNOWN and SENSOR_ERROR: both LEDs off.
  digitalWrite(greenPins[slot], slotState[slot] == AVAILABLE ? HIGH : LOW);
  digitalWrite(redPins[slot],   slotState[slot] == OCCUPIED  ? HIGH : LOW);
}

void updateLcd() {
  uint8_t freeCount = 0, occupiedCount = 0;
  for (uint8_t i = 0; i < SLOT_COUNT; i++) {
    if (slotState[i] == AVAILABLE) freeCount++;
    if (slotState[i] == OCCUPIED)  occupiedCount++;
  }

  char line1[17];
  char line2[17];
  snprintf(line1, sizeof(line1), "Free:%u Occ:%u %s",
           freeCount, occupiedCount, mqtt.connected() ? "ON" : "--");
  snprintf(line2, sizeof(line2), "S1:%c S2:%c S3:%c",
           stateLetter(slotState[0]), stateLetter(slotState[1]),
           stateLetter(slotState[2]));

  lcd.setCursor(0, 0);
  lcd.print(line1);
  for (size_t i = strlen(line1); i < 16; i++) lcd.print(' ');
  lcd.setCursor(0, 1);
  lcd.print(line2);
  for (size_t i = strlen(line2); i < 16; i++) lcd.print(' ');
}

float readDistanceCm(uint8_t slot) {
  digitalWrite(trigPins[slot], LOW);
  delayMicroseconds(3);
  digitalWrite(trigPins[slot], HIGH);
  delayMicroseconds(10);
  digitalWrite(trigPins[slot], LOW);

  unsigned long duration = pulseIn(echoPins[slot], HIGH, ECHO_TIMEOUT_US);
  if (duration == 0) {
    return -1.0;  // no echo / timeout
  }
  return (duration * 0.0343f) / 2.0f;
}

void publishSlotStatus(uint8_t slot) {
  if (!mqtt.connected()) return;
  if (slotState[slot] == UNKNOWN) return;  // nothing confirmed yet

  char topic[48];
  snprintf(topic, sizeof(topic), "smartparking/slot%u/status", slot + 1);

  uint32_t seq = ++messageSeq;
  unsigned long uptime = millis();
  char canonical[128];
  snprintf(canonical, sizeof(canonical), "status|%u|%s|%.1f|%lu|%s|%lu",
           slot + 1, stateName(slotState[slot]), lastDistanceCm[slot],
           uptime, bootId, (unsigned long)seq);
  char sig[65];
  signMessage(canonical, sig);

  char payload[256];
  snprintf(payload, sizeof(payload),
           "{\"slot\":%u,\"status\":\"%s\",\"distance_cm\":%.1f,"
           "\"uptime_ms\":%lu,\"boot\":\"%s\",\"seq\":%lu,\"sig\":\"%s\"}",
           slot + 1, stateName(slotState[slot]), lastDistanceCm[slot],
           uptime, bootId, (unsigned long)seq, sig);

  // Retained, so a dashboard that connects later still gets the latest state.
  bool ok = mqtt.publish(topic, payload, true);
  Serial.printf("Status publish %s: %s [%s]\n", topic, stateName(slotState[slot]),
                ok ? "OK" : "FAILED");
}

void publishSlotEvent(uint8_t slot, SlotState oldState, SlotState newState) {
  if (!mqtt.connected()) return;

  char topic[48];
  snprintf(topic, sizeof(topic), "smartparking/slot%u/event", slot + 1);

  uint32_t seq = ++messageSeq;
  unsigned long uptime = millis();
  char canonical[140];
  snprintf(canonical, sizeof(canonical), "event|%u|%s|%s|%.1f|%lu|%s|%lu",
           slot + 1, stateName(oldState), stateName(newState),
           lastDistanceCm[slot], uptime, bootId, (unsigned long)seq);
  char sig[65];
  signMessage(canonical, sig);

  char payload[280];
  snprintf(payload, sizeof(payload),
           "{\"slot\":%u,\"from\":\"%s\",\"to\":\"%s\",\"distance_cm\":%.1f,"
           "\"uptime_ms\":%lu,\"boot\":\"%s\",\"seq\":%lu,\"sig\":\"%s\"}",
           slot + 1, stateName(oldState), stateName(newState),
           lastDistanceCm[slot], uptime, bootId, (unsigned long)seq, sig);

  // Not retained: an event describes a change that just happened.
  mqtt.publish(topic, payload, false);
}

void changeSlotState(uint8_t slot, SlotState newState) {
  if (newState == slotState[slot]) return;

  SlotState oldState = slotState[slot];
  slotState[slot] = newState;
  setIndicators(slot);
  lcdDirty = true;

  // Keep this exact format: tests/wokwi/slot_detection.test.yaml waits for it.
  Serial.printf("Slot %u: %s -> %s\n", slot + 1, stateName(oldState), stateName(newState));
  Serial.printf("  distance: %.1f cm\n", lastDistanceCm[slot]);

  publishSlotEvent(slot, oldState, newState);
  publishSlotStatus(slot);
}

void processSensorReading(uint8_t slot, float distance) {
  if (distance < 0) {
    errorStreak[slot]++;
    validStreak[slot] = 0;
    occupiedStreak[slot] = 0;
    availableStreak[slot] = 0;

    if (errorStreak[slot] >= SENSOR_ERROR_READINGS) {
      lastDistanceCm[slot] = -1.0;  // report "no valid reading", not an old value
      changeSlotState(slot, SENSOR_ERROR);
    }
    return;
  }

  lastDistanceCm[slot] = distance;
  errorStreak[slot] = 0;
  validStreak[slot]++;

  if (distance < OCCUPIED_THRESHOLD_CM) {
    occupiedStreak[slot]++;
    availableStreak[slot] = 0;
    if (occupiedStreak[slot] >= CONFIRMATION_READINGS &&
        validStreak[slot] >= CONFIRMATION_READINGS) {
      changeSlotState(slot, OCCUPIED);
    }
  } else {
    availableStreak[slot]++;
    occupiedStreak[slot] = 0;
    if (availableStreak[slot] >= CONFIRMATION_READINGS &&
        validStreak[slot] >= CONFIRMATION_READINGS) {
      changeSlotState(slot, AVAILABLE);
    }
  }
}

// -------------------- MQTT callback --------------------
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, TOPIC_COMMAND) != 0) return;
  if (length > 16) return;  // ignore oversized commands

  char message[17];
  memcpy(message, payload, length);
  message[length] = '\0';
  String command(message);
  command.trim();
  command.toUpperCase();

  if (command != "REFRESH" && command != "STATUS") return;

  // Rate limit: a flood of commands cannot make the device flood the broker.
  unsigned long now = millis();
  if (lastCommandAt != 0 && now - lastCommandAt < COMMAND_MIN_GAP_MS) {
    Serial.println("Command ignored (rate limit)");
    return;
  }
  lastCommandAt = now;

  Serial.printf("Command: %s\n", command.c_str());
  for (uint8_t i = 0; i < SLOT_COUNT; i++) {
    publishSlotStatus(i);
  }
}

// -------------------- Connection management --------------------
void startWifiConnection() {
  if (WiFi.status() == WL_CONNECTED) return;

  unsigned long now = millis();
  if (now - lastWifiAttempt < WIFI_RETRY_INTERVAL_MS) return;

  lastWifiAttempt = now;
  Serial.println("Retrying Wi-Fi connection...");
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD, 6);
}

void tryMqttConnection() {
  if (WiFi.status() != WL_CONNECTED || mqtt.connected()) return;

  unsigned long now = millis();
  if (now - lastMqttAttempt < MQTT_RETRY_INTERVAL_MS) return;
  lastMqttAttempt = now;

  Serial.print("Attempting MQTT (TLS) connection... ");

  // Last Will: the broker publishes this signed OFFLINE message if the
  // device disappears without disconnecting cleanly.
  buildConnectionPayload("OFFLINE", willPayload, sizeof(willPayload));

  bool connected = mqtt.connect(mqttClientId.c_str(), TOPIC_CONNECTION, 0, true,
                                willPayload);
  if (connected) {
    Serial.println("connected");
    char onlinePayload[200];
    buildConnectionPayload("ONLINE", onlinePayload, sizeof(onlinePayload));
    mqtt.publish(TOPIC_CONNECTION, onlinePayload, true);
    mqtt.subscribe(TOPIC_COMMAND);

    // Re-send the current state after every reconnection.
    for (uint8_t i = 0; i < SLOT_COUNT; i++) {
      publishSlotStatus(i);
    }
  } else {
    Serial.printf("failed, state=%d\n", mqtt.state());
  }
  lcdDirty = true;
}

// -------------------- Arduino setup and loop --------------------
void setup() {
  Serial.begin(115200);
  delay(100);

  for (uint8_t i = 0; i < SLOT_COUNT; i++) {
    pinMode(trigPins[i], OUTPUT);
    pinMode(echoPins[i], INPUT);
    pinMode(greenPins[i], OUTPUT);
    pinMode(redPins[i], OUTPUT);
    digitalWrite(trigPins[i], LOW);
    digitalWrite(greenPins[i], LOW);
    digitalWrite(redPins[i], LOW);
  }

  Wire.begin(LCD_SDA, LCD_SCL);
  lcd.init();
  lcd.backlight();
  lcd.setCursor(0, 0);
  lcd.print("Smart Parking");
  lcd.setCursor(0, 1);
  lcd.print("Starting...");

  snprintf(bootId, sizeof(bootId), "%08lx", (unsigned long)esp_random());
  mqttClientId = "SmartParking-";
  mqttClientId += String((uint32_t)ESP.getEfuseMac(), HEX);

  netClient.setCACert(ROOT_CA);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(mqttCallback);
  mqtt.setBufferSize(512);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(5);

  // Start Wi-Fi without waiting: sensing and LEDs work from the first second.
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD, 6);
  lastWifiAttempt = millis();

  Serial.println();
  Serial.println("=== SMART PARKING SYSTEM STARTED ===");
  Serial.println("Firmware v2.0");
  Serial.printf("%u parking slots configured.\n", SLOT_COUNT);
  Serial.printf("Threshold: %.0f cm\n", OCCUPIED_THRESHOLD_CM);
  Serial.printf("Boot ID: %s\n", bootId);
  Serial.println("MQTT topics: smartparking/slotN/status (TLS, signed)");
}

void loop() {
  // Network upkeep never blocks local sensing for long.
  startWifiConnection();

  bool wifiConnected = (WiFi.status() == WL_CONNECTED);
  if (wifiConnected != wifiWasConnected) {
    wifiWasConnected = wifiConnected;
    lcdDirty = true;
    if (wifiConnected) {
      Serial.print("Wi-Fi CONNECTED! IP Address: ");
      Serial.println(WiFi.localIP());
    } else {
      Serial.println("Wi-Fi disconnected");
    }
  }

  if (wifiConnected) {
    tryMqttConnection();
  }
  if (mqtt.connected()) {
    mqtt.loop();
  }

  // Scan all sensors at a fixed interval.
  unsigned long now = millis();
  if (now - lastSensorScan >= SENSOR_INTERVAL_MS) {
    lastSensorScan = now;
    for (uint8_t i = 0; i < SLOT_COUNT; i++) {
      float distance = readDistanceCm(i);
      processSensorReading(i, distance);
      Serial.printf("Slot %u distance: %.1f cm | state: %s\n", i + 1, distance,
                    stateName(slotState[i]));
    }
  }

  // Periodic retained status heartbeat (skips slots that are still UNKNOWN).
  now = millis();
  if (mqtt.connected() && now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
    lastHeartbeat = now;
    for (uint8_t i = 0; i < SLOT_COUNT; i++) {
      publishSlotStatus(i);
    }
  }

  // LCD: redraw on change, at most once per second.
  now = millis();
  if (lcdDirty && now - lastLcdUpdate >= LCD_REFRESH_MS) {
    lastLcdUpdate = now;
    lcdDirty = false;
    updateLcd();
  }
}
