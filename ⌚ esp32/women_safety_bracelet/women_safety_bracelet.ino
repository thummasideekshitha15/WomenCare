/*
 * ============================================================
 *  Women Safety Bracelet — ESP32 Firmware
 *  WiFi Manager + Triple Tap Detection + Firebase Alert
 * ============================================================
 *
 *  HOW IT WORKS:
 *  1. On boot → tries saved WiFi from flash memory
 *  2. No saved WiFi OR fails in 10s
 *       → hotspot "WomenSafety-Setup" (pass: safety123)
 *       → connect phone → open 192.168.4.1
 *       → pick WiFi + enter password → Save
 *  3. Saves to flash, connects, starts monitoring
 *  4. New WiFi fails → back to hotspot automatically
 *
 *  RESET WiFi: Hold vibration sensor HIGH for 3s on boot
 * ============================================================
 */

#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <HTTPClient.h>

// ── Pins ───────────────────────────────────────────────────────────────────
#define VIB_SENSOR  10
#define LED_PIN      8

// ── Hotspot ────────────────────────────────────────────────────────────────
const char*     AP_SSID     = "WomenSafety-Setup";
const char*     AP_PASSWORD = "safety123";
const IPAddress AP_IP(192, 168, 4, 1);

// ── Firebase ───────────────────────────────────────────────────────────────
const String FIREBASE_URL =
    "https://women-safety-d12d5-default-rtdb.firebaseio.com/threat_detect/state.json";

// ── Tap Detection ──────────────────────────────────────────────────────────
int           tapCount      = 0;
unsigned long firstTapTime  = 0;
const int     TAP_WINDOW_MS = 1000;

// ── Objects ────────────────────────────────────────────────────────────────
Preferences prefs;
WebServer   server(80);

// ── State ──────────────────────────────────────────────────────────────────
bool   inSetupMode     = false;
String savedSSID       = "";
String savedPassword   = "";
String pendingSSID     = "";
String pendingPassword = "";
bool   connectPending  = false;

// ══════════════════════════════════════════════════════════════════════════
//  FLASH STORAGE
// ══════════════════════════════════════════════════════════════════════════

void saveCredentials(String ssid, String pass) {
    prefs.begin("wifi", false);
    prefs.putString("ssid", ssid);
    prefs.putString("password", pass);
    prefs.end();
    Serial.println("✅ Saved to flash.");
}

void loadCredentials() {
    prefs.begin("wifi", true);
    savedSSID     = prefs.getString("ssid",     "");
    savedPassword = prefs.getString("password", "");
    prefs.end();
    Serial.print("📂 Saved SSID: ");
    Serial.println(savedSSID.length() > 0 ? savedSSID : "(none)");
}

void clearCredentials() {
    prefs.begin("wifi", false);
    prefs.clear();
    prefs.end();
    savedSSID = savedPassword = "";
    Serial.println("🗑️ Credentials cleared.");
}

// ══════════════════════════════════════════════════════════════════════════
//  SETUP PORTAL PAGES
// ══════════════════════════════════════════════════════════════════════════

String buildNetworkOptions() {
    int found = WiFi.scanNetworks();
    String options = "";
    for (int i = 0; i < found; i++) {
        String name = WiFi.SSID(i);
        options += "<option value='" + name + "'>" + name
                +  " (" + String(WiFi.RSSI(i)) + " dBm)</option>\n";
    }
    if (found == 0) options = "<option value=''>No networks found</option>";
    return options;
}

String buildSetupPage(String message = "") {
    String opts = buildNetworkOptions();
    String msg  = message.length() > 0
        ? "<div class='err'>" + message + "</div>" : "";

    return R"rawhtml(
<!DOCTYPE html><html>
<head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta charset='UTF-8'>
<title>Women Safety — WiFi Setup</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,Arial,sans-serif;background:#0a0f1e;color:#f0f0f5;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .card{background:#111827;border-radius:16px;padding:32px 28px;max-width:420px;
        width:100%;border:1px solid #6B21A8;box-shadow:0 0 30px rgba(107,33,168,0.3)}
  .logo{text-align:center;font-size:48px;margin-bottom:8px}
  h1{text-align:center;font-size:20px;color:#C4B5FD;margin-bottom:4px}
  .sub{text-align:center;font-size:13px;color:#6B7280;margin-bottom:24px}
  label{display:block;font-size:13px;color:#9CA3AF;margin:16px 0 6px}
  select,input{width:100%;padding:12px 14px;background:#1F2937;border:1px solid #374151;
               border-radius:10px;color:#F9FAFB;font-size:15px;outline:none}
  select:focus,input:focus{border-color:#7C3AED;box-shadow:0 0 0 2px rgba(124,58,237,0.3)}
  .or{text-align:center;color:#4B5563;font-size:12px;margin:10px 0 4px}
  button{width:100%;padding:14px;background:linear-gradient(135deg,#7C3AED,#BE185D);
         border:none;border-radius:10px;color:#fff;font-size:16px;font-weight:bold;
         cursor:pointer;margin-top:24px;letter-spacing:.5px}
  button:active{opacity:.85}
  .err{background:#991B1B22;border:1px solid #EF4444;border-radius:8px;
       padding:10px 14px;color:#FCA5A5;font-size:13px;margin-bottom:16px}
  .info{background:#065F4622;border:1px solid #10B981;border-radius:8px;
        padding:10px 14px;color:#6EE7B7;font-size:12px;margin-top:16px;text-align:center}
</style>
</head>
<body><div class='card'>
  <div class='logo'>🛡️</div>
  <h1>Women Safety Bracelet</h1>
  <p class='sub'>Connect device to your WiFi network</p>
  )rawhtml" + msg + R"rawhtml(
  <form action='/connect' method='POST'>
    <label>Select Network</label>
    <select name='ssid'>)rawhtml" + opts + R"rawhtml(</select>
    <p class='or'>— or type manually —</p>
    <input type='text' name='manual_ssid' placeholder='Type WiFi name (optional)'>
    <label>Password</label>
    <input type='password' name='password' placeholder='Enter WiFi password'>
    <button type='submit'>🔗 Connect &amp; Save</button>
  </form>
  <div class='info'>
    📱 Connect phone to:<br>
    <strong>WomenSafety-Setup</strong> / pass: <strong>safety123</strong>
  </div>
</div></body></html>
)rawhtml";
}

String buildSuccessPage(String ssid) {
    return R"rawhtml(
<!DOCTYPE html><html>
<head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Connecting...</title>
<style>
  body{font-family:Arial,sans-serif;background:#0a0f1e;color:#f0f0f5;
       display:flex;align-items:center;justify-content:center;
       min-height:100vh;text-align:center;padding:20px}
  .card{background:#111827;border-radius:16px;padding:40px 28px;
        max-width:380px;border:1px solid #10B981}
  .icon{font-size:60px;margin-bottom:16px}
  h2{color:#10B981;margin-bottom:12px}
  p{color:#9CA3AF;font-size:14px;line-height:1.6}
  .ssid{color:#C4B5FD;font-weight:bold}
</style>
</head>
<body><div class='card'>
  <div class='icon'>✅</div>
  <h2>Connecting...</h2>
  <p>Trying to connect to<br>
  <span class='ssid'>)rawhtml" + ssid + R"rawhtml(</span></p>
  <p style='margin-top:16px'>
    LED glows solid when connected.<br><br>
    If it fails, setup page will reappear automatically.
  </p>
</div></body></html>
)rawhtml";
}

// ── Web Server Handlers ────────────────────────────────────────────────────

void handleRoot() {
    server.send(200, "text/html", buildSetupPage());
}

void handleConnect() {
    String manual   = server.arg("manual_ssid");
    String selected = server.arg("ssid");
    String password = server.arg("password");
    String chosen   = (manual.length() > 0) ? manual : selected;

    if (chosen.length() == 0) {
        server.send(200, "text/html",
            buildSetupPage("⚠️ Please select or enter a network name."));
        return;
    }

    Serial.print("🔐 Submitted SSID: ");
    Serial.println(chosen);
    server.send(200, "text/html", buildSuccessPage(chosen));

    pendingSSID     = chosen;
    pendingPassword = password;
    connectPending  = true;
}

void handle404() {
    server.sendHeader("Location", "http://192.168.4.1", true);
    server.send(302, "text/plain", "");
}

// ── Hotspot Start / Stop ───────────────────────────────────────────────────

void startSetupMode() {
    inSetupMode = true;
    Serial.println("📶 Starting setup hotspot...");

    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(AP_IP, AP_IP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(AP_SSID, AP_PASSWORD);

    Serial.println("Hotspot: WomenSafety-Setup");
    Serial.println("Open:    http://192.168.4.1");

    server.on("/",        HTTP_GET,  handleRoot);
    server.on("/connect", HTTP_POST, handleConnect);
    server.onNotFound(handle404);
    server.begin();

    // Rapid blink = setup mode
    for (int i = 0; i < 6; i++) {
        digitalWrite(LED_PIN, HIGH); delay(100);
        digitalWrite(LED_PIN, LOW);  delay(100);
    }
}

void stopSetupMode() {
    server.stop();
    WiFi.softAPdisconnect(true);
    inSetupMode = false;
}

// ══════════════════════════════════════════════════════════════════════════
//  WiFi CONNECTION — 10 second timeout
// ══════════════════════════════════════════════════════════════════════════

bool connectToWiFi(String ssid, String pass) {
    Serial.print("📡 Connecting to: ");
    Serial.println(ssid);

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), pass.c_str());

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > 10000) {
            Serial.println("\n❌ Timed out (10s)");
            WiFi.disconnect(true);
            return false;
        }
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
        Serial.print(".");
        delay(300);
    }

    digitalWrite(LED_PIN, HIGH);   // solid = connected
    Serial.println("\n✅ Connected!");
    Serial.println(WiFi.localIP());
    return true;
}

// ══════════════════════════════════════════════════════════════════════════
//  FIREBASE
// ══════════════════════════════════════════════════════════════════════════

void sendToFirebase() {
    Serial.println("🚨 Sending alert to Firebase...");

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi lost — reconnecting...");
        if (!connectToWiFi(savedSSID, savedPassword)) {
            startSetupMode();
            return;
        }
    }

    HTTPClient http;
    http.begin(FIREBASE_URL);
    http.addHeader("Content-Type", "application/json");
    int code = http.PUT("true");
    Serial.print(code > 0 ? "✅ Firebase OK: " : "❌ Firebase failed: ");
    Serial.println(code);
    http.end();
}

// ══════════════════════════════════════════════════════════════════════════
//  SETUP
// ══════════════════════════════════════════════════════════════════════════

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n══════════════════════════════");
    Serial.println("  Women Safety Bracelet Boot");
    Serial.println("══════════════════════════════");

    pinMode(VIB_SENSOR, INPUT);
    pinMode(LED_PIN,    OUTPUT);

    // Hold sensor HIGH for 3s on boot = force WiFi reset
    Serial.println("Hold sensor 3s to reset WiFi...");
    bool forceReset = true;
    unsigned long holdStart = millis();
    while (millis() - holdStart < 3000) {
        if (digitalRead(VIB_SENSOR) == LOW) {
            forceReset = false;
            break;
        }
        delay(100);
    }
    if (forceReset) {
        Serial.println("🔄 Clearing saved WiFi credentials");
        clearCredentials();
    }

    // Try saved credentials
    loadCredentials();
    if (savedSSID.length() > 0) {
        Serial.println("🔑 Trying saved WiFi...");
        if (connectToWiFi(savedSSID, savedPassword)) {
            Serial.println("🟢 Ready — watching for triple tap");
            return;
        }
        Serial.println("⚠️ Saved WiFi failed — starting setup portal");
    } else {
        Serial.println("⚠️ No saved WiFi — starting setup portal");
    }

    startSetupMode();
}

// ══════════════════════════════════════════════════════════════════════════
//  LOOP
// ══════════════════════════════════════════════════════════════════════════

void loop() {

    // ── Setup Mode ────────────────────────────────────────────────────────
    if (inSetupMode) {
        server.handleClient();

        if (connectPending) {
            connectPending = false;
            stopSetupMode();
            delay(500);

            if (connectToWiFi(pendingSSID, pendingPassword)) {
                saveCredentials(pendingSSID, pendingPassword);
                savedSSID     = pendingSSID;
                savedPassword = pendingPassword;
                Serial.println("🟢 Connected and saved!");
            } else {
                Serial.println("❌ Failed — back to setup portal");
                startSetupMode();
            }
        }
        return;
    }

    // ── Normal Mode: Triple Tap Detection ─────────────────────────────────
    if (digitalRead(VIB_SENSOR) == HIGH) {
        if (tapCount == 0) {
            firstTapTime = millis();
            Serial.println("Tap 1 — window started");
        }
        tapCount++;
        Serial.print("Tap #");
        Serial.println(tapCount);
        delay(150);  // debounce
    }

    if (tapCount > 0 && millis() - firstTapTime > TAP_WINDOW_MS) {
        if (tapCount == 3) {
            Serial.println("🚨 TRIPLE TAP — sending Firebase alert!");
            digitalWrite(LED_PIN, !digitalRead(LED_PIN));
            sendToFirebase();
        } else {
            Serial.print("Got ");
            Serial.print(tapCount);
            Serial.println(" taps — need exactly 3, ignoring");
        }
        tapCount = 0;
        Serial.println("──────────────────────────────");
    }
}
 
