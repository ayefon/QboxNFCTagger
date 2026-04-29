/**
 * MIFARE Classic NFC + BLE Bridge
 * Seeed Studio XIAO ESP32-C3 + PN532 NFC module (I2C mode, polled)
 *
 * Reads and writes MIFARE Classic 1K/4K tags via the PN532,
 * and exposes all operations over BLE using the Nordic UART Service.
 * Uses NimBLE-Arduino for BLE — lower RAM and better behavior than
 * the stock ESP32 BLE library.
 *
 * This is a port of NFC_BLE_Bridge.ino (Arduino Nano 33 BLE / nRF52840),
 * following PORTING_SPEC.md. The BLE GATT contract (§3), command
 * protocol (§4), response strings (§4.9), concurrency model (§5.2),
 * auth retry (§5.3), fixed-buffer discipline (§5.4), 1K/4K sector
 * helpers (§6), and fatal blink codes (§7) are preserved.
 *
 * ── Required Libraries ───────────────────────────────────────────────────────
 *   NimBLE-Arduino   (Tools → Manage Libraries → NimBLE-Arduino, v2.x)
 *   PN532            (Tools → Manage Libraries → "PN532" by elechouse)
 *                    Install BOTH of these from that package:
 *                       - PN532 (core protocol)
 *                       - PN532_I2C (I2C HAL)
 *                    The Adafruit_PN532 library's I2C path is unreliable
 *                    on ESP32 — InListPassiveTarget silently drops bytes
 *                    even though getFirmwareVersion works. The Elechouse
 *                    library is the known-good path on ESP32.
 *
 * ── Board setup ──────────────────────────────────────────────────────────────
 *   Install the "esp32 by Espressif Systems" board package via the Boards
 *   Manager (2.0.14 or newer recommended).
 *   Tools → Board → ESP32 Arduino → "XIAO_ESP32C3"
 *   Tools → USB CDC On Boot → Enabled  (required for USB serial logging)
 *
 * ── Wiring (I2C mode, polled — IRQ and RSTO unused) ─────────────────────────
 *   PN532 VCC  → 3V3
 *   PN532 GND  → GND
 *   PN532 SDA  → D4  (GPIO6, default Wire SDA on XIAO ESP32-C3)
 *   PN532 SCL  → D5  (GPIO7, default Wire SCL on XIAO ESP32-C3)
 *   PN532 IRQ  → (not connected)
 *   PN532 RSTO → (not connected, or tied to VCC via the breakout's pull-up)
 *
 *   PN532 jumpers / switches set to I2C mode:
 *     SEL0 = ON  (high)
 *     SEL1 = OFF (low)
 *
 * ── Status LED ───────────────────────────────────────────────────────────────
 *   The XIAO ESP32-C3 has no user-controllable onboard LED. Wire an LED +
 *   ~330 Ω series resistor between D10 (GPIO10) and GND. Active HIGH.
 *   - Disconnected : ~1 Hz blink (500 ms on / 500 ms off)
 *   - Connected    : solid on
 *   - Fatal init   : N short pulses, 1.2 s pause, repeat (N=2 PN532, N=3 BLE)
 *   To use a different pin, change LED_PIN below.
 *
 * ── BLE Protocol (NUS / Nordic UART Service) ─────────────────────────────────
 *   Identical to the Nano 33 BLE reference — same UUIDs, same device name
 *   ("NFC-BLE-Bridge"), same command vocabulary, same response strings.
 *   Existing clients (phone apps, SwiftUI NFCBLEManager, etc.) work
 *   unchanged. Responses are chunked into ≤ 20-byte notifications with a
 *   trailing "\n" notification marking end-of-message.
 */

#include <NimBLEDevice.h>
#include <Wire.h>
#include <PN532_I2C.h>
#include <PN532.h>

// ── Pin definitions ───────────────────────────────────────────────────────────
// The Elechouse PN532 library's I2C HAL does not need IRQ or RSTO wired —
// PN532_I2C polls the ready byte over I2C and never pulses reset.

// XIAO ESP32-C3 default I2C pins (D4 / D5 on the silkscreen).
#define I2C_SDA_PIN      6       // D4 silkscreen = GPIO6
#define I2C_SCL_PIN      7       // D5 silkscreen = GPIO7

// No user LED on this board — wire an external LED to D10.
#ifndef LED_BUILTIN
#define LED_BUILTIN      10      // D10 silkscreen = GPIO10
#endif
#define LED_PIN          LED_BUILTIN

// ── Config ────────────────────────────────────────────────────────────────────
#define BLE_DEVICE_NAME   "NFC-BLE-Bridge"
#define NUS_SERVICE_UUID  "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define NUS_RX_UUID       "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
#define NUS_TX_UUID       "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
#define USB_BAUD          115200
#define TOTAL_BLOCKS      64        // 64 for MIFARE Classic 1K, 256 for 4K
// MIFARE Classic 4K layout: blocks 0..127 live in 32 "small" sectors of 4
// blocks each (sectors 0..31), and blocks 128..255 live in 8 "big" sectors
// of 16 blocks each (sectors 32..39). 1K cards only have the first region.
#define MFC_BIG_SECTOR_FIRST_BLOCK 128
#define MFC_SMALL_SECTOR_SIZE       4
#define MFC_BIG_SECTOR_SIZE        16
#define BLE_MTU           20        // spec §3.3: ≤ 20-byte notification chunks

// I2C timing tuning — increase if you see intermittent auth failures.
#define I2C_SETTLE_MS     50
#define AUTH_RETRIES      3

// Maximum time readPassiveTargetID blocks looking for a tag before it gives
// up and we emit "ERR No tag found". The portable spec §4.1 says "up to
// 2000 ms"; we run shorter so the response comes back before mobile-app
// read-operation timers (~1.5–3 s on many NUS clients) expire — otherwise
// the operator re-taps and gets "ERR Busy" while the first SCAN is still
// polling. Raise toward 2000 if you want spec-literal timing.
#define TAG_SCAN_TIMEOUT_MS 1000

// Fixed-buffer sizing — no String churn in hot paths (spec §5.4).
#define CMD_BUF_LEN       96
#define RESP_BUF_LEN      128

// ── Objects ───────────────────────────────────────────────────────────────────
PN532_I2C pn532i2c(Wire);
PN532     nfc(pn532i2c);

NimBLEServer*         pServer = nullptr;
NimBLECharacteristic* rxChar  = nullptr;   // central → peripheral
NimBLECharacteristic* txChar  = nullptr;   // peripheral → central (notify)

// bleSend is called both from the main task (command handlers) and from
// the NimBLE host task (RX write callback emitting "OK Cancelling" /
// "ERR Busy" / etc.). A mutex serializes setValue+notify so chunks from
// concurrent senders don't interleave.
SemaphoreHandle_t bleSendMutex = nullptr;

// ── State ─────────────────────────────────────────────────────────────────────
volatile bool bleConnected = false;
uint8_t keyA[6]     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t keyB[6]     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// 'A' selects keyA + MIFARE_CMD_AUTH_A; 'B' selects keyB + MIFARE_CMD_AUTH_B.
char    authMode    = 'A';

// Accumulator for bytes arriving over BLE (consumed by the RX callback).
char    cmdBuffer[CMD_BUF_LEN];
size_t  cmdLen = 0;

// 1-slot queue (spec §5.2): a complete line waiting for loop() to dispatch.
char    pendingCmd[CMD_BUF_LEN];
volatile bool pendingReady   = false;
volatile bool commandRunning = false;

// Set from the RX callback (NimBLE task) when CANCEL arrives during a
// running command. Polled by cmdDump between blocks.
volatile bool cancelRequested = false;

// ── Helpers ───────────────────────────────────────────────────────────────────

void bleSend(const char* msg) {
  Serial.println(msg);
  if (!bleConnected || txChar == nullptr) return;
  if (bleSendMutex) xSemaphoreTake(bleSendMutex, portMAX_DELAY);
  size_t len = strlen(msg);
  for (size_t i = 0; i < len; i += BLE_MTU) {
    size_t chunk = len - i;
    if (chunk > BLE_MTU) chunk = BLE_MTU;
    txChar->setValue((const uint8_t*)(msg + i), chunk);
    txChar->notify();
  }
  txChar->setValue((const uint8_t*)"\n", 1);
  txChar->notify();
  if (bleSendMutex) xSemaphoreGive(bleSendMutex);
}

static char hexNibble(uint8_t n) {
  return n < 10 ? ('0' + n) : ('A' + n - 10);
}

// Case-insensitive string equality for short ASCII keywords.
static bool eqIgnoreCase(const char* a, const char* b) {
  while (*a && *b) {
    char ca = *a, cb = *b;
    if (ca >= 'a' && ca <= 'z') ca -= 32;
    if (cb >= 'a' && cb <= 'z') cb -= 32;
    if (ca != cb) return false;
    a++; b++;
  }
  return *a == '\0' && *b == '\0';
}

// Writes 2*len uppercase hex chars + null terminator into `out`.
// Caller must provide a buffer of at least 2*len + 1 bytes.
void toHex(const uint8_t* buf, uint8_t len, char* out) {
  for (uint8_t i = 0; i < len; i++) {
    out[i * 2]     = hexNibble(buf[i] >> 4);
    out[i * 2 + 1] = hexNibble(buf[i] & 0x0F);
  }
  out[len * 2] = '\0';
}

// Parse up to `maxLen` bytes from `hexLen` hex chars at `hex`.
int fromHex(const char* hex, size_t hexLen, uint8_t* buf, int maxLen) {
  int count = 0;
  for (size_t i = 0; i + 1 < hexLen && count < maxLen; i += 2) {
    char pair[3] = {hex[i], hex[i + 1], '\0'};
    buf[count++] = (uint8_t)strtol(pair, nullptr, 16);
  }
  return count;
}

// MIFARE Classic sector-layout helpers. Correct for both 1K and 4K cards.
static bool isSectorStart(uint16_t block) {
  if (block < MFC_BIG_SECTOR_FIRST_BLOCK) return (block % MFC_SMALL_SECTOR_SIZE) == 0;
  return ((block - MFC_BIG_SECTOR_FIRST_BLOCK) % MFC_BIG_SECTOR_SIZE) == 0;
}

static bool isSectorTrailer(uint16_t block) {
  if (block < MFC_BIG_SECTOR_FIRST_BLOCK) return ((block + 1) % MFC_SMALL_SECTOR_SIZE) == 0;
  return ((block - MFC_BIG_SECTOR_FIRST_BLOCK + 1) % MFC_BIG_SECTOR_SIZE) == 0;
}

static uint16_t sectorOf(uint16_t block) {
  if (block < MFC_BIG_SECTOR_FIRST_BLOCK) return block / MFC_SMALL_SECTOR_SIZE;
  return 32 + (block - MFC_BIG_SECTOR_FIRST_BLOCK) / MFC_BIG_SECTOR_SIZE;
}

// Auth with retry loop — fixes intermittent I2C timing failures.
// A failed auth leaves the PN532 in a state where further auth attempts
// will also fail until the tag is re-activated, so re-select between tries.
bool authBlockWithRetry(uint8_t block, uint8_t uid[], uint8_t uidLen) {
  for (uint8_t attempt = 0; attempt < AUTH_RETRIES; attempt++) {
    if (attempt > 0) {
      delay(I2C_SETTLE_MS);
      uint8_t retryUid[7];
      uint8_t retryUidLen;
      nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, retryUid, &retryUidLen, 1000);
      delay(I2C_SETTLE_MS);
    }
    uint8_t* key     = (authMode == 'B') ? keyB : keyA;
    uint8_t  cmdAuth = (authMode == 'B') ? MIFARE_CMD_AUTH_B : MIFARE_CMD_AUTH_A;
    if (nfc.mifareclassic_AuthenticateBlock(uid, uidLen, block, cmdAuth, key)) {
      return true;
    }
  }
  return false;
}

// Fatal init error: blink `code` pulses on LED_PIN, pause, repeat forever.
// Also re-prints `msg` to Serial on each cycle so a late-attached USB host
// sees the diagnostic.
//   code 2 = PN532 not found
//   code 3 = BLE init failed
void fatalBlink(uint8_t code, const char* msg) {
  pinMode(LED_PIN, OUTPUT);
  while (true) {
    Serial.println(msg);
    for (uint8_t i = 0; i < code; i++) {
      digitalWrite(LED_PIN, HIGH); delay(200);
      digitalWrite(LED_PIN, LOW);  delay(200);
    }
    delay(1200);
  }
}

// ── Command handlers ──────────────────────────────────────────────────────────

void cmdScan() {
  uint8_t uid[7], uidLen;
  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, TAG_SCAN_TIMEOUT_MS)) {
    char uidHex[15];
    toHex(uid, uidLen, uidHex);
    char resp[RESP_BUF_LEN];
    snprintf(resp, sizeof(resp), "OK UID:%s", uidHex);
    bleSend(resp);
  } else {
    bleSend("ERR No tag found");
  }
}

void cmdRead(uint8_t block) {
  uint8_t uid[7], uidLen;
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, TAG_SCAN_TIMEOUT_MS)) {
    bleSend("ERR No tag found"); return;
  }
  delay(I2C_SETTLE_MS);

  char resp[RESP_BUF_LEN];
  if (!authBlockWithRetry(block, uid, uidLen)) {
    snprintf(resp, sizeof(resp), "ERR Auth failed block %u", (unsigned)block);
    bleSend(resp); return;
  }
  uint8_t data[16];
  if (nfc.mifareclassic_ReadDataBlock(block, data)) {
    char dataHex[33];
    toHex(data, 16, dataHex);
    snprintf(resp, sizeof(resp), "OK B%u:%s", (unsigned)block, dataHex);
  } else {
    snprintf(resp, sizeof(resp), "ERR Read failed block %u", (unsigned)block);
  }
  bleSend(resp);
}

void cmdWrite(uint8_t block, const char* hexData, size_t hexLen) {
  if (hexLen != 32) {
    bleSend("ERR Need exactly 32 hex chars (16 bytes)"); return;
  }
  char resp[RESP_BUF_LEN];
  if (isSectorTrailer(block)) {
    snprintf(resp, sizeof(resp), "ERR Block %u is a sector trailer — skipped", (unsigned)block);
    bleSend(resp); return;
  }
  uint8_t uid[7], uidLen;
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, TAG_SCAN_TIMEOUT_MS)) {
    bleSend("ERR No tag found"); return;
  }
  delay(I2C_SETTLE_MS);

  if (!authBlockWithRetry(block, uid, uidLen)) {
    snprintf(resp, sizeof(resp), "ERR Auth failed block %u", (unsigned)block);
    bleSend(resp); return;
  }
  uint8_t data[16];
  fromHex(hexData, hexLen, data, 16);
  if (nfc.mifareclassic_WriteDataBlock(block, data)) {
    snprintf(resp, sizeof(resp), "OK Written block %u", (unsigned)block);
  } else {
    snprintf(resp, sizeof(resp), "ERR Write failed block %u", (unsigned)block);
  }
  bleSend(resp);
}

void cmdDump() {
  uint8_t uid[7], uidLen;
  if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, TAG_SCAN_TIMEOUT_MS)) {
    bleSend("ERR No tag found"); return;
  }
  delay(I2C_SETTLE_MS);

  char uidHex[15];
  toHex(uid, uidLen, uidHex);
  char resp[RESP_BUF_LEN];
  snprintf(resp, sizeof(resp), "OK DUMP START UID:%s", uidHex);
  bleSend(resp);

  // uint16_t because TOTAL_BLOCKS=256 (4K) would wrap a uint8_t counter.
  bool sectorAuthed = false;
  for (uint16_t block = 0; block < TOTAL_BLOCKS; block++) {
    if (isSectorStart(block)) {
      sectorAuthed = authBlockWithRetry((uint8_t)block, uid, uidLen);
      if (!sectorAuthed) {
        snprintf(resp, sizeof(resp), "ERR Auth failed sector %u", (unsigned)sectorOf(block));
        bleSend(resp);
      }
    }
    if (!sectorAuthed) {
      // NimBLE runs on its own FreeRTOS task, so no poll() is needed —
      // cancelRequested is already updated by the RX callback.
      if (cancelRequested) { bleSend("ERR DUMP cancelled"); return; }
      continue;
    }
    uint8_t data[16];
    if (nfc.mifareclassic_ReadDataBlock((uint8_t)block, data)) {
      char dataHex[33];
      toHex(data, 16, dataHex);
      snprintf(resp, sizeof(resp), "B%u:%s", (unsigned)block, dataHex);
    } else {
      snprintf(resp, sizeof(resp), "ERR Read failed block %u", (unsigned)block);
    }
    bleSend(resp);
    if (cancelRequested) {
      bleSend("ERR DUMP cancelled");
      return;
    }
    delay(2);   // brief yield to the NimBLE task
  }
  bleSend("OK DUMP END");
}

void cmdSetKey(const char* hexKey, size_t hexLen, uint8_t* keyBuf) {
  if (hexLen != 12) {
    bleSend("ERR Key must be 12 hex chars (6 bytes)"); return;
  }
  fromHex(hexKey, hexLen, keyBuf, 6);
  char resp[RESP_BUF_LEN];
  snprintf(resp, sizeof(resp), "OK Key set:%.*s", (int)hexLen, hexKey);
  bleSend(resp);
}

// ── Command parser ────────────────────────────────────────────────────────────
// `cmd` is a mutable null-terminated buffer. Parsed in place.
void processCommand(char* cmd) {
  size_t len = strlen(cmd);
  while (len > 0 && (cmd[len - 1] == ' ' || cmd[len - 1] == '\t')) {
    cmd[--len] = '\0';
  }
  char* p = cmd;
  while (*p == ' ' || *p == '\t') p++;
  for (char* q = p; *q; q++) {
    if (*q >= 'a' && *q <= 'z') *q -= 32;
  }
  Serial.print("CMD: "); Serial.println(p);

  if (strcmp(p, "SCAN") == 0) {
    cmdScan();

  } else if (strncmp(p, "READ ", 5) == 0) {
    int block = atoi(p + 5);
    if (block < 0 || block >= TOTAL_BLOCKS) { bleSend("ERR Invalid block"); return; }
    cmdRead((uint8_t)block);

  } else if (strncmp(p, "WRITE ", 6) == 0) {
    char* args  = p + 6;
    char* space = strchr(args, ' ');
    if (!space) { bleSend("ERR Usage: WRITE <block> <32 hex chars>"); return; }
    *space = '\0';
    int    block   = atoi(args);
    char*  data    = space + 1;
    size_t dataLen = strlen(data);
    if (block < 0 || block >= TOTAL_BLOCKS) { bleSend("ERR Invalid block"); return; }
    cmdWrite((uint8_t)block, data, dataLen);

  } else if (strcmp(p, "DUMP") == 0) {
    cmdDump();

  } else if (strncmp(p, "KEYA ", 5) == 0) {
    cmdSetKey(p + 5, strlen(p + 5), keyA);

  } else if (strncmp(p, "KEYB ", 5) == 0) {
    cmdSetKey(p + 5, strlen(p + 5), keyB);

  } else if (strncmp(p, "AUTHMODE ", 9) == 0) {
    const char* arg = p + 9;
    if ((arg[0] == 'A' || arg[0] == 'B') && arg[1] == '\0') {
      authMode = arg[0];
      char resp[RESP_BUF_LEN];
      snprintf(resp, sizeof(resp), "OK AUTHMODE:%c", authMode);
      bleSend(resp);
    } else {
      bleSend("ERR AUTHMODE must be A or B");
    }

  } else {
    char resp[RESP_BUF_LEN];
    snprintf(resp, sizeof(resp), "ERR Unknown command: %s", p);
    bleSend(resp);
  }
}

// ── BLE event handlers ────────────────────────────────────────────────────────

class ServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* server, NimBLEConnInfo& info) override {
    bleConnected = true;
    digitalWrite(LED_PIN, HIGH);
    Serial.print("BLE connected: ");
    Serial.print(info.getAddress().toString().c_str());
    Serial.println(info.isEncrypted() ? " (paired)" : " (pairing required)");
  }

  void onDisconnect(NimBLEServer* server, NimBLEConnInfo& info, int reason) override {
    bleConnected = false;
    cmdLen       = 0;
    cmdBuffer[0] = '\0';
    pendingReady = false;
    // If a handler is mid-flight on the main loop (e.g. DUMP), let it finish
    // naturally. cancelRequested tells it to bail out of long work early.
    cancelRequested = commandRunning;
    digitalWrite(LED_PIN, LOW);
    Serial.println("BLE disconnected — advertising...");
    NimBLEDevice::startAdvertising();
  }

  // LESC numeric comparison: NimBLE hands us the 6-digit value both sides
  // should be showing. Log it so the user can compare against the central's
  // display (MITM protection), then auto-accept. No persistent bond storage
  // is wired up, so the bond lasts only until reboot.
  void onConfirmPassKey(NimBLEConnInfo& info, uint32_t pin) override {
    char buf[32];
    snprintf(buf, sizeof(buf), "PAIRING CODE: %06lu", (unsigned long)pin);
    Serial.println(buf);
    NimBLEDevice::injectConfirmPasskey(info, true);
  }

  void onAuthenticationComplete(NimBLEConnInfo& info) override {
    Serial.print("BLE auth complete: ");
    Serial.println(info.isEncrypted() ? "encrypted" : "not encrypted");
  }
};

// Called on every BLE write to the RX characteristic. Runs on the NimBLE
// host task. Must not do slow work: it accumulates bytes, and when a
// complete line arrives either hands it to loop() via pendingCmd or
// handles CANCEL / Busy inline.
class RxCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& info) override {
    NimBLEAttValue value = c->getValue();
    const uint8_t* data  = value.data();
    size_t         len   = value.size();
    for (size_t i = 0; i < len; i++) {
      char ch = (char)data[i];
      if (ch == '\n' || ch == '\r') {
        if (cmdLen == 0) continue;
        cmdBuffer[cmdLen] = '\0';

        // Trim trailing whitespace for the CANCEL check.
        size_t end = cmdLen;
        while (end > 0 && (cmdBuffer[end - 1] == ' ' || cmdBuffer[end - 1] == '\t')) {
          cmdBuffer[--end] = '\0';
        }
        const char* line = cmdBuffer;
        while (*line == ' ' || *line == '\t') line++;

        if (eqIgnoreCase(line, "CANCEL")) {
          if (commandRunning) {
            cancelRequested = true;
            bleSend("OK Cancelling");
          } else {
            bleSend("ERR Nothing to cancel");
          }
        } else if (pendingReady || commandRunning) {
          bleSend("ERR Busy");
        } else {
          // Hand the line off to loop() for dispatch.
          strncpy(pendingCmd, line, sizeof(pendingCmd) - 1);
          pendingCmd[sizeof(pendingCmd) - 1] = '\0';
          pendingReady = true;
        }
        cmdLen = 0;

      } else if (cmdLen < CMD_BUF_LEN - 1) {
        cmdBuffer[cmdLen++] = ch;
      }
      // Overflow is silently truncated; the parser will surface an
      // "Unknown command" once the line terminator arrives.
    }
  }
};

// ── Setup ─────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(USB_BAUD);
  // Wait briefly for a USB host, but don't block headless/battery boot.
  for (uint32_t start = millis(); !Serial && millis() - start < 2000; ) {}

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  Wire.begin(I2C_SDA_PIN, I2C_SCL_PIN);
  Wire.setClock(100000);   // PN532 is happy at 100 kHz; ESP32 defaults higher
  // The PN532 clock-stretches the I2C bus while it processes InListPassiveTarget.
  // ESP32-C3's Wire has a short default bus timeout (~50 ms) — a stretched
  // transaction then returns prematurely and the library sees "no response"
  // which surfaces as a phantom "No tag found". Give the bus plenty of slack.
  Wire.setTimeOut(1000);
  nfc.begin();
  // Adafruit_PN532::begin() internally calls Wire.begin() with no args, which
  // on some ESP32 core versions resets the pin assignment or clock. Reassert
  // all three here so the PN532 transactions land on the right bus at 100 kHz
  // with the extended bus timeout.
  Wire.begin(I2C_SDA_PIN, I2C_SCL_PIN);
  Wire.setClock(100000);
  Wire.setTimeOut(1000);

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    fatalBlink(2, "ERROR: PN532 not found — check wiring and I2C jumpers!");
  }
  Serial.print("PN532 firmware v");
  Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata >> 8) & 0xFF, DEC);
  nfc.SAMConfig();
  // Bound the PN532's internal RF retry count. Each MxRtyPassiveActivation
  // cycle runs ~100 ms at the RF level, and the library-level timeout on
  // readPassiveTargetID does NOT abort a PN532 mid-flight — it waits for
  // the PN532 to finish its internal retries before returning. So the
  // effective no-tag response time is dominated by this value × ~100 ms,
  // not by our TAG_SCAN_TIMEOUT_MS. Keep it low enough to return quickly,
  // high enough to reliably catch a tag that was placed just before the
  // SCAN arrived. 5 ≈ ~500 ms worst-case no-tag; a tag that's present
  // typically answers on the first cycle.
  nfc.setPassiveActivationRetries(0x05);
  delay(250);   // SAMConfig settle — longer on ESP32-C3 than on nRF52

  bleSendMutex = xSemaphoreCreateMutex();

  NimBLEDevice::init(BLE_DEVICE_NAME);
  NimBLEDevice::setPower(9);    // ESP32-C3 max TX power (+9 dBm)

  // Pairing exposure (spec §3.4):
  //  - bonding = false : no persistent LTK/IRK storage; bond lasts until reboot
  //  - mitm    = true  : request MITM protection (numeric comparison)
  //  - sc      = true  : use LE Secure Connections
  // IO capability DISPLAY_YESNO + onConfirmPasskey gives numeric comparison,
  // matching the ArduinoBLE reference's setDisplayCode() behavior.
  NimBLEDevice::setSecurityAuth(false, true, true);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO);

  pServer = NimBLEDevice::createServer();
  if (!pServer) {
    fatalBlink(3, "ERROR: BLE init failed!");
  }
  pServer->setCallbacks(new ServerCallbacks());

  NimBLEService* pService = pServer->createService(NUS_SERVICE_UUID);

  // Neither characteristic requires encryption (spec §3.4) — requiring it
  // without persistent bond storage causes client timeouts with many NUS
  // apps. Pairing is still exposed above; it's just not enforced at GATT.
  txChar = pService->createCharacteristic(
    NUS_TX_UUID,
    NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  rxChar = pService->createCharacteristic(
    NUS_RX_UUID,
    NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rxChar->setCallbacks(new RxCallbacks());

  pService->start();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(NUS_SERVICE_UUID);
  adv->setName(BLE_DEVICE_NAME);
  adv->enableScanResponse(true);
  NimBLEDevice::startAdvertising();

  Serial.println("NFC BLE Bridge ready — advertising as \"" BLE_DEVICE_NAME "\"");
}

// ── Loop ──────────────────────────────────────────────────────────────────────
void loop() {
  // Dispatch any command queued by the RX callback. Runs on the main task
  // so long operations (DUMP) don't block the NimBLE host task — the BLE
  // callback keeps firing, so a mid-flight CANCEL can set cancelRequested.
  if (pendingReady && !commandRunning) {
    commandRunning  = true;
    cancelRequested = false;
    pendingReady    = false;
    processCommand(pendingCmd);
    commandRunning  = false;
    cancelRequested = false;
  }

  if (!bleConnected) {
    digitalWrite(LED_PIN, (millis() / 500) % 2);
  }
  delay(10);
}
