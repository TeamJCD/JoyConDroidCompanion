#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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

# _orig.so variants come first: when the module is already installed the
# bind-mount overlays the canonical name with the shim, but leaves the
# renamed original accessible as *_orig.so in the same directory.
CANDIDATES=(
    "/apex/com.android.btservices/lib64/libbluetooth_jni_orig.so"
    "/apex/com.android.btservices/lib64/libbluetooth_jni.so"
    "/apex/com.android.bt/lib64/libbluetooth_jni_orig.so"
    "/apex/com.android.bt/lib64/libbluetooth_jni.so"
    "/vendor/lib64/libbluetooth_qti_jni_orig.so"
    "/vendor/lib64/libbluetooth_qti_jni.so"
    "/system/lib64/libbluetooth_qti_jni_orig.so"
    "/system/lib64/libbluetooth_qti_jni.so"
    "/system/system_ext/lib64/libbluetooth_qti_jni_orig.so"
    "/system/system_ext/lib64/libbluetooth_qti_jni.so"
    "/vendor/lib64/libbluetooth_qti_orig.so"
    "/vendor/lib64/libbluetooth_qti.so"
    "/system/lib64/libbluetooth_qti_orig.so"
    "/system/lib64/libbluetooth_qti.so"
    "/system/system_ext/lib64/libbluetooth_qti_orig.so"
    "/system/system_ext/lib64/libbluetooth_qti.so"
    "/system/lib64/libbluetooth_orig.so"
    "/system/lib64/libbluetooth.so"
)

REMOTE_PATH=""
for cand in "${CANDIDATES[@]}"; do
    result=$(adb shell "[ -f '$cand' ] && echo yes || echo no" 2>/dev/null | tr -d '\r\n')
    if [ "$result" = "yes" ]; then
        REMOTE_PATH="$cand"
        break
    fi
done

if [ -z "$REMOTE_PATH" ]; then
    echo "error: no supported libbluetooth*.so found on device" >&2
    exit 1
fi

# Always save under the canonical name (strip _orig suffix if present).
LIBNAME=$(basename "$REMOTE_PATH")
LIBNAME="${LIBNAME/_orig.so/.so}"
OUT="$SCRIPT_DIR/libs/$MANUFACTURER/$MODEL/$LIBNAME"
mkdir -p "$(dirname "$OUT")"

echo "Device: $MANUFACTURER $MODEL"
echo "Remote: $REMOTE_PATH"
echo "Local:  $OUT"
adb pull "$REMOTE_PATH" "$OUT"
