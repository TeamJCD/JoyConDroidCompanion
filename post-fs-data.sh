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

# Pre-create /dev/btaddr so the BT shim (bluetooth domain) can write to it.
# Needs to exist before BT starts; post-fs-data.sh runs as root before any service.
touch /dev/btaddr
chown bluetooth:bluetooth /dev/btaddr
chmod 0644 /dev/btaddr
chcon u:object_r:bluetooth_data_file:s0 /dev/btaddr

APEX_LIB=/apex/com.android.btservices/lib64

if [ -f "$APEX_LIB/libbluetooth_jni.so" ]; then
    setup_overlay "$APEX_LIB" libbluetooth_jni.so
elif [ -f /vendor/lib64/libbluetooth_qti.so ]; then
    setup_overlay /vendor/lib64 libbluetooth_qti.so
elif [ -f /system/lib64/libbluetooth_qti.so ]; then
    setup_overlay /system/lib64 libbluetooth_qti.so
elif [ -f /system/system_ext/lib64/libbluetooth_qti.so ]; then
    setup_overlay /system/system_ext/lib64 libbluetooth_qti.so
elif [ -f /system/lib64/libbluetooth.so ]; then
    setup_overlay /system/lib64 libbluetooth.so
fi
