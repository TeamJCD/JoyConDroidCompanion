# Joy-Con Droid Companion

A Magisk module that patches the Android Bluetooth stack at runtime to fix
connectivity issues between [Joy-Con Droid](https://github.com/TeamJCD/JoyConDroid)
and the Switch family of consoles.

## Background

Joy-Con Droid broadcasts Class of Device (CoD) `0x180508` because Android's HID
profile registration (`BluetoothHidDevice.registerApp()`) sets service class bits
that real Joy-Con hardware does not have. The correct CoD is `0x002508`.

**Switch 1:** The wrong CoD can cause discovery or connection issues. This module
replaces the `system.prop`-based approach used by SwitchControllerCOD with an
active hook that corrects the CoD on every HCI write, surviving any subsequent
Android stack overrides.

**Switch 2:** Filters incoming connections strictly by CoD service class bits and
ignores `0x180508` entirely. Additionally, without bonding bits in the SSP IO
capability exchange the Android stack classifies the pairing as temporary, skips
storing the link key, and the subsequent L2CAP reconnect is rejected with
Security\_Block.

## How It Works

The module has two components:

### BT Stack Shim

Auto-detects the Bluetooth library on the device (APEX-based `libbluetooth_jni.so`,
system/vendor `libbluetooth.so`, Qualcomm `libbluetooth_qti.so`, `system_ext`-based
QTI variant, or the older split-stack `libbluetooth_jni.so`/`libbluetooth_qti_jni.so`
— see below) and replaces it with a matching shim via a bind-mount overlay. The shim
loads the original library alongside itself and installs two inline trampoline hooks:

| Hook | Target function | Effect |
|------|----------------|--------|
| 1 | `btsnd_hcic_write_dev_class` | Forces CoD to `0x002508` on every HCI write |
| 2 | `btm_set_bond_type_dev` | Upgrades temporary bonds to persistent |

Both functions are located by pattern-scanning the executable segment of the
loaded library — no hardcoded offsets, no debug symbols required.

Some vendor Bluetooth stacks restructure the code enough that the generic
Hook 2 scan finds nothing (confirmed on Samsung's Android 16 "Gabeldorsche"
stack, e.g. Galaxy Z Fold SM-F946B). For those, the module tries a second,
still scan-based strategy that looks for the target function's own
instruction shape instead of anchoring on its (in this case unrecognizable)
caller — see `src/bond_setter_scan.c`.

On some (typically older, pre-mainline-APEX) BT stacks, `JNI_OnLoad` lives in
a separate, thin wrapper library from the one containing the CoD/Bond target
functions — the latter is loaded alongside it as an unmodified `DT_NEEDED`
dependency. The shim always scans the library it hooked `JNI_OnLoad` in
first; if neither target is found there, it sweeps the other known library
names still resolvable in `/proc/self/maps` — no hardcoded pairing between
the two files required. If a target still isn't found at that point (the
vendor lib may not be mapped yet due to async stack init), the whole scan
retries from a background thread every 300ms for up to ~12s before giving
up.

A separate JNI library (`libjoycondroid_jni.so`) is deployed into the Joy-Con Droid
app directory. It provides `getBluetoothAddressNative`, which reads the host Bluetooth
MAC address from `/dev/btaddr` — a value otherwise unavailable to non-system apps on
Android 10+ due to the `LOCAL_MAC_ADDRESS` permission requirement.

### Runtime Resource Overlay (RRO)

Some devices ship with `profile_supported_hid_device` set to `false` in
`com.android.bluetooth`, which prevents Joy-Con Droid from registering as a HID
device. The module includes a static RRO (`com.github.teamjcd.joycondroidcompanion.rro.hid.apk`)
that forces this resource to `true` at boot.

The APK is installed to `system/vendor/overlay/com.github.teamjcd.joycondroidcompanion.rro.hid/`
inside the Magisk module and is applied automatically — no manual overlay activation required.

Only the HID Device profile is enabled; HID Host is left untouched because Joy-Con
Droid only uses `BluetoothHidDevice`, not `BluetoothHidHost`.

## Requirements

**To build:**

- Android SDK command-line tools (`sdkmanager`) — included with [Android Studio](https://developer.android.com/studio) or the [standalone command line tools](https://developer.android.com/studio#command-line-tools-only)
- Android NDK r27d (`27.3.13750724`), build-tools 37.0.0, platform-36 — run `make sdk` to install via sdkmanager
- `zip`
- JDK (for `jarsigner` and `keytool`; `keytool` only needed when no keystore is provided via `RRO_KEYSTORE_B64`)

**To install:**

- Android 9+ device with Magisk
- [Joy-Con Droid](https://github.com/TeamJCD/JoyConDroid) installed

## Building

```sh
make zip
```

Output: `build/JoyConDroidCompanion.zip`

### First-time setup

Install all required SDK components:

```sh
export ANDROID_HOME=$HOME/Android/Sdk
make sdk   # NDK r27d + build-tools 37.0.0 + platform-36
```

### NDK path

The build system looks for the NDK at `$ANDROID_HOME/ndk/27.3.13750724` by default.
Override with `NDK_DIR` if your NDK is installed elsewhere:

```sh
make zip NDK_DIR=/path/to/android-ndk-r27d
```

### RRO signing

Without any environment variables set, `make zip` generates a temporary keystore
automatically (requires `keytool` from the JDK on `PATH`). To use a persistent
keystore, set these variables before running `make zip`:

| Variable | Default | Description |
|----------|---------|-------------|
| `RRO_KEYSTORE_B64` | *(unset)* | Base64-encoded keystore file; if unset, a fresh keystore is generated |
| `RRO_STOREPASS` | `jcdcrro` | Keystore password |
| `RRO_KEYPASS` | `jcdcrro` | Key password |
| `RRO_ALIAS` | `jcdcrro` | Key alias |

## Installation

```sh
adb push build/JoyConDroidCompanion.zip /sdcard/
```

In the Magisk app: **Modules → Install from storage**, select the ZIP, then reboot.

## Verification

After reboot, start Joy-Con Droid and enable pairing mode. Check that the CoD is
correct from a Linux host:

```sh
sudo hcitool inq
# Expected: class: 0x002508
```

Hook installation and firing is logged under the `jcdshim` tag:

```sh
adb logcat -s jcdshim
```

Expected on Bluetooth start:

```
jcdshim  I  JNI_OnLoad: shim loaded
jcdshim  I  JNI_OnLoad: orig lib = libbluetooth_jni_orig.so
jcdshim  I  patch_fn: hooked 0x...    ← Hook 1 (CoD slot 0) installed
jcdshim  I  patch_fn: hooked 0x...    ← Hook 1 (CoD slot 1, Samsung only)
jcdshim  I  patch_fn: hooked 0x...    ← Hook 2 installed
jcdshim  I  JNI_OnLoad: done
```

The `patch_fn` line will include `(mem)` when patching via `/proc/self/mem`
(Samsung Knox devices) or `(mprotect)` on standard builds.

Expected during pairing with Switch 2:

```
jcdshim  I  hook_cod[0]: CoD=0x180508 -> forcing 0x002508
jcdshim  I  hook_bond_type: bond_type=2
jcdshim  I  hook_bond_type: TEMPORARY -> PERSISTENT
```

## Debugging

If the module appears installed but hooks do not fire (nothing in `jcdshim` logcat
after Bluetooth is active), the Bluetooth process may not have restarted since boot.
Force a clean restart to get a fresh log:

```sh
adb logcat -c && \
adb shell "am force-stop com.android.bluetooth; sleep 3; svc bluetooth enable" && \
sleep 8 && \
adb logcat -s jcdshim -d
```

Expected output:

```
jcdshim  I  JNI_OnLoad: shim loaded
jcdshim  I  JNI_OnLoad: orig lib = libbluetooth_jni_orig.so
jcdshim  I  patch_fn: hooked 0x...    ← Hook 1 (CoD) installed
jcdshim  I  patch_fn: hooked 0x...    ← Hook 2 (Bond) installed
jcdshim  I  JNI_OnLoad: done
jcdshim  I  hook_cod[0]: CoD=0x... -> forcing 0x002508
jcdshim  I  write_bt_addr: wrote XX:XX:XX:XX:XX:XX to /dev/btaddr
```

If `patch_fn: hooked` lines are missing, the pattern scanner did not find the target
function — the OEM may have a modified BT stack. Open an issue using the steps in
[Filing a Bug Report](#filing-a-bug-report) below.

## Fetching Libraries from a Device

`scripts/pull.sh` (Linux/macOS) and `scripts/pull.ps1` (Windows PowerShell 5.1+)
pull the correct `libbluetooth*.so` from a connected device via `adb` and save it
to `scripts/libs/<Manufacturer>/<Model>/`. The search order mirrors
`post-fs-data.sh`: APEX → vendor QTI → system QTI → system_ext QTI → system.

```sh
# Linux / macOS
bash scripts/pull.sh

# Windows (PowerShell 5.1+)
.\scripts\pull.ps1
```

The pulled file can then be passed to `scripts/verify_hooks.py` to confirm the
pattern scanner finds both hooks before flashing.

## Static Pattern Verification

`scripts/verify_hooks.py` statically scans a `libbluetooth*.so` for the same
patterns used by the runtime hooks — no device required:

```sh
# Scan a specific library pulled from a device
python3 scripts/verify_hooks.py "scripts/libs/Sony/Xperia XZ2 Compact/libbluetooth_jni.so"

# Auto-scan all reference libraries under scripts/libs/
python3 scripts/verify_hooks.py
```

For each library the script reports the function address found, the
`bond_type_ptr` location, the struct field offsets, and the prologue type:

```
======================================================================
  scripts/./libs/Sony/Xperia XZ2 Compact/libbluetooth_jni.so
======================================================================
  Exec segment: 0x002ac000 – 0x00bcf9c0  (9358 KiB)
  Hook 1 (CoD):  fn=0x00895ee0  (+48 bytes to MOVZ)  ✅
  Hook 2 (Bond): fn=0x00830f14  bond_type_ptr=0x00c54658  offs=264/265/266  ✅
             first 4 insns: 0xf800865e 0xa9bd7bfd 0xf9000bf5 0xa9024ff4
             prologue: SCS_SAVE (standard)
```

Samsung devices ship multiple functions that send Write\_Class\_of\_Device.
All hookable candidates are listed; functions that use `x0` as a structure
pointer instead of a raw CoD value are skipped automatically (`⏭`):

```
======================================================================
  scripts/libs/samsung/SM-A055M/libbluetooth_jni.so
======================================================================
  Exec segment: 0x002c9000 – 0x00c04f70  (9455 KiB)
  Hook 1 (CoD):  fn=0x00382b20  (+52 bytes to MOVZ)  ✅
  Hook 1 (CoD):  fn=0x00aa74d0  (+48 bytes to MOVZ)      (slot 1)
  Hook 1 (CoD):  fn=0x007a1b70  (+96 bytes to MOVZ)  ⏭  (x0=pointer, skipped)
  Hook 2 (Bond): fn=0x00a44330  bond_type_ptr=0x00cef4f0  offs=264/265/266  ✅
             first 4 insns: 0xb0001628 0x911d0108 0xf9410108 0xb40002a8
             prologue: ADRP x8 (Samsung-style early-exit preamble)
```

The script exits non-zero if any library yields no match, making it suitable
as a pre-flash check for new firmware images. Use `scripts/pull.sh` (Linux/macOS)
or `scripts/pull.ps1` (Windows) to pull a library from a connected device first.

If the generic Hook 2 scan finds nothing but the setter-shape scan (see
above) matches, the script reports that instead of a plain failure:

```
  Hook 2 (Bond): generic scanner found nothing, but setter-shape scan  ✅  (bond_setter_scan.c, fn=0x008ed088)
```

## Filing a Bug Report

`scripts/collect_info.sh` (Linux/macOS) and `scripts/collect_info.ps1` (Windows
PowerShell 5.1+) collect all information required by the GitHub issue template in
one step. The script also restarts Bluetooth automatically to capture the logcat.

```sh
# Linux / macOS
bash scripts/collect_info.sh

# Windows (PowerShell 5.1+)
.\scripts\collect_info.ps1
```

Copy the output into the corresponding fields of the bug report form.
