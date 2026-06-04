#!/bin/bash
# Collects device info needed for a JoyConDroidCompanion bug report.
# Restarts Bluetooth at the end to capture the jcdshim logcat.
set -uo pipefail

if ! command -v adb &>/dev/null; then
    echo "error: adb not found in PATH" >&2
    exit 1
fi

MANUFACTURER=$(adb shell getprop ro.product.manufacturer 2>/dev/null | tr -d '\r\n')
MODEL=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r\n')

if [ -z "$MANUFACTURER" ] || [ -z "$MODEL" ]; then
    echo "error: no device connected" >&2
    exit 1
fi

echo "Collecting device info ..."

ANDROID=$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r\n')
FINGERPRINT=$(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r\n')
SECURITY=$(adb shell getprop ro.build.version.security_patch 2>/dev/null | tr -d '\r\n')
SOC_MFR=$(adb shell getprop ro.soc.manufacturer 2>/dev/null | tr -d '\r\n')
SOC_MODEL=$(adb shell getprop ro.soc.model 2>/dev/null | tr -d '\r\n')
ROM=$(adb shell getprop ro.build.display.id 2>/dev/null | tr -d '\r\n')

MAGISK=$(adb shell magisk -v 2>/dev/null | tr -d '\r\n' || true)
[ -z "$MAGISK" ] && MAGISK="(not found)"

BT_LIB=$(adb shell \
    "ls /apex/com.android.btservices/lib64/libbluetooth_jni.so \
        /vendor/lib64/libbluetooth_qti.so \
        /system/lib64/libbluetooth_qti.so \
        /system/lib64/libbluetooth.so 2>/dev/null" \
    | tr -d '\r')

SELINUX=$(adb shell getenforce 2>/dev/null | tr -d '\r\n')

JCD_VER=$(adb shell \
    "dumpsys package com.rdapps.gamepad 2>/dev/null | grep versionName | cut -d= -f2" \
    | tr -d '\r\n' || true)
[ -z "$JCD_VER" ] && JCD_VER="(not installed)"

echo "Restarting Bluetooth to capture jcdshim logcat (~15 seconds) ..."
adb logcat -c
adb shell "am force-stop com.android.bluetooth; sleep 3; svc bluetooth enable; sleep 8"
LOGCAT=$(adb logcat -s jcdshim libc crash_dump64 -d 2>/dev/null)

printf '\n'
printf '══════════════════════════════════════════════════════════════════════\n'
printf '  JoyConDroidCompanion – Issue Info Collector\n'
printf '  Paste each value into the corresponding GitHub issue field.\n'
printf '══════════════════════════════════════════════════════════════════════\n'
printf '\n'
printf 'Issue title:            [%s %s] <short description>\n' "$MANUFACTURER" "$MODEL"
printf '\n'
printf 'Device:                 %s %s\n' "$MANUFACTURER" "$MODEL"
printf 'Android version:        %s\n' "$ANDROID"
printf 'Build fingerprint:      %s\n' "$FINGERPRINT"
printf 'Security patch date:    %s\n' "$SECURITY"
printf 'SoC:                    %s %s\n' "$SOC_MFR" "$SOC_MODEL"
printf 'ROM:                    %s\n' "$ROM"
printf 'Magisk version:         %s\n' "$MAGISK"
printf 'Bluetooth library path: %s\n' "$BT_LIB" | sed 's/^/  /'
printf 'SELinux mode:           %s\n' "$SELINUX"
printf 'Joy-Con Droid version:  %s\n' "$JCD_VER"
printf '\n'
printf '─────────────────────── Logs ───────────────────────\n'
printf '%s\n' "$LOGCAT"
printf '────────────────────────────────────────────────────\n'
