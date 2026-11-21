#!/system/bin/sh
MODDIR="${0%/*}"

chmod 755 "$MODDIR/patch_sym"

# Sets up a bind-mount overlay over LIB_DIR, replacing LIB_NAME with the shim.
# The original is copied as LIB_NAME → ${LIB_NAME%.so}_orig.so with its SONAME
# patched to .sx so the linker does not deduplicate it against the shim.
setup_overlay() {
    local LIB_DIR="$1"
    local LIB_NAME="$2"
    local ORIG_NAME="${LIB_NAME%.so}_orig.so"
    local OVERLAY=/dev/btlib64

    mkdir -p "$OVERLAY"

    for f in "$LIB_DIR"/*; do
        [ -f "$f" ] || continue
        bn=$(basename "$f")
        cp "$f" "$OVERLAY/$bn"
        chcon u:object_r:system_lib_file:s0 "$OVERLAY/$bn"
    done

    cp "$LIB_DIR/$LIB_NAME" "$OVERLAY/$ORIG_NAME"
    "$MODDIR/patch_sym" "$OVERLAY/$ORIG_NAME" \
        "$LIB_NAME" "${LIB_NAME%.so}.sx"
    chcon u:object_r:system_lib_file:s0 "$OVERLAY/$ORIG_NAME"

    cp "$MODDIR/${LIB_NAME%.so}_shim.so" "$OVERLAY/$LIB_NAME"
    chcon u:object_r:system_lib_file:s0 "$OVERLAY/$LIB_NAME"

    mount --bind "$OVERLAY" "$LIB_DIR"
}

# KernelSU (and some Magisk variants) run post-fs-data before APEXes are fully
# activated, so the overlay may not have been created yet. Re-run the detection
# here in service.sh as a fallback, then restart Bluetooth to load the shim.
OVERLAYED=0
if [ ! -d /dev/btlib64 ]; then
    APEX_LIB=/apex/com.android.btservices/lib64
    APEX_LIB_LEGACY=/apex/com.android.bt/lib64

    if [ -f "$APEX_LIB/libbluetooth_jni.so" ]; then
        setup_overlay "$APEX_LIB" libbluetooth_jni.so
        OVERLAYED=1
    elif [ -f "$APEX_LIB_LEGACY/libbluetooth_jni.so" ]; then
        setup_overlay "$APEX_LIB_LEGACY" libbluetooth_jni.so
        OVERLAYED=1
    elif [ -f /vendor/lib64/libbluetooth_qti.so ]; then
        setup_overlay /vendor/lib64 libbluetooth_qti.so
        OVERLAYED=1
    elif [ -f /system/lib64/libbluetooth_qti.so ]; then
        setup_overlay /system/lib64 libbluetooth_qti.so
        OVERLAYED=1
    elif [ -f /system/system_ext/lib64/libbluetooth_qti.so ]; then
        setup_overlay /system/system_ext/lib64 libbluetooth_qti.so
        OVERLAYED=1
    elif [ -f /system/lib64/libbluetooth.so ]; then
        setup_overlay /system/lib64 libbluetooth.so
        OVERLAYED=1
    fi
fi

# Ensure /dev/btaddr exists and is writable by the bluetooth domain.
if [ ! -e /dev/btaddr ]; then
    touch /dev/btaddr
    chown bluetooth:bluetooth /dev/btaddr
    chmod 0644 /dev/btaddr
    chcon u:object_r:bluetooth_data_file:s0 /dev/btaddr
fi

# Deploy the JNI helper into Joy-Con Droid's app directory.
APP_DIR=$(find /data/app -maxdepth 3 -type d \
    -name "com.rdapps.gamepad-*" 2>/dev/null | head -1)
if [ -n "$APP_DIR" ]; then
    APP_LIB="$APP_DIR/lib/arm64"
    mkdir -p "$APP_LIB"
    cp "$MODDIR/libjoycondroid_jni.so" "$APP_LIB/libjoycondroid_jni.so"
    chmod 755 "$APP_LIB/libjoycondroid_jni.so"
    chcon u:object_r:apk_data_file:s0 "$APP_LIB/libjoycondroid_jni.so"
fi

# If we installed an overlay in this service.sh run, restart the Bluetooth stack
# so the shim is loaded. On Magisk the overlay is usually already in place from
# post-fs-data, so this branch is skipped.
if [ "$OVERLAYED" -eq 1 ]; then
    am force-stop com.android.bluetooth
    svc bluetooth disable
    sleep 2
    svc bluetooth enable
fi
