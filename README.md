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

The module auto-detects the Bluetooth library on the device (APEX-based
`libbluetooth_jni.so`, system/vendor `libbluetooth.so`, or Qualcomm
`libbluetooth_qti.so`) and replaces it with a matching shim via a bind-mount
overlay. The shim loads the original library alongside itself and installs two
inline trampoline hooks:

| Hook | Target function | Effect |
|------|----------------|--------|
| 1 | `btsnd_hcic_write_dev_class` | Forces CoD to `0x002508` on every HCI write |
| 2 | `btm_set_bond_type_dev` | Upgrades temporary bonds to persistent |

Both functions are located by pattern-scanning the executable segment of the
loaded library — no hardcoded offsets, no debug symbols required.

A separate JNI library (`libjoycondroid_jni.so`) is deployed into the Joy-Con Droid
app directory. It provides `getBluetoothAddressNative`, which reads the host Bluetooth
MAC address from `/dev/btaddr` — a value otherwise unavailable to non-system apps on
Android 10+ due to the `LOCAL_MAC_ADDRESS` permission requirement.

## Requirements

**To build:**

- Android NDK r30 (`30.0.14904198`) — run `make ndk` to install via sdkmanager
- `zip`

**To install:**

- Android device with Magisk
- [Joy-Con Droid](https://github.com/TeamJCD/JoyConDroid) installed

## Building

```sh
make zip
```

Output: `build/JoyConDroidCompanion.zip`

### NDK path

The build system looks for the NDK at `$ANDROID_HOME/ndk/30.0.14904198` by default.
Override with `NDK_DIR` if your NDK is installed elsewhere:

```sh
make zip NDK_DIR=/path/to/android-ndk-r30
```

Or export it permanently:

```sh
export ANDROID_HOME=$HOME/Android/Sdk
make zip
```

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
jcdshim  I  patch_fn: hooked 0x...    ← Hook 1 installed
jcdshim  I  patch_fn: hooked 0x...    ← Hook 2 installed
jcdshim  I  JNI_OnLoad: done
```

Expected during pairing with Switch 2:

```
jcdshim  I  hook_cod: CoD=0x180508 -> forcing 0x002508
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
jcdshim  I  patch_fn: hooked 0x...    ← Hook 1 installed
jcdshim  I  patch_fn: hooked 0x...    ← Hook 2 installed
jcdshim  I  JNI_OnLoad: done
jcdshim  I  hook_cod: CoD=0x... -> forcing 0x002508
jcdshim  I  write_bt_addr: wrote XX:XX:XX:XX:XX:XX to /dev/btaddr
```

If `patch_fn: hooked` lines are missing, the pattern scanner did not find the target
function — the OEM may have a modified BT stack. Open an issue and attach the output
of `adb logcat -s jcdshim` and `adb shell getprop ro.build.fingerprint`.
