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

# Non-APEX /system/lib64: hand the shim and the patched original to Magisk's
# Magic Mount instead of bind-mounting a copy of the whole directory. The
# copy approach drops subdirectories (hw/, drm/, ...) and hard-codes the
# Android 10+ label system_lib_file, which does not exist on Android 9.
# Magisk runs module post-fs-data scripts before it applies module files, so
# files placed under $MODDIR/system/ here are mounted in the same boot, and
# /system still shows the unmodified original at this point.
setup_magic_mount() {
    local LIB_NAME="$1"
    local SRC="/system/lib64/$LIB_NAME"
    local ORIG_NAME="${LIB_NAME%.so}_orig.so"
    local DST="$MODDIR/system/lib64"
    local CTX

    CTX=$(ls -Z "$SRC" 2>/dev/null | awk '{print $1}')
    case "$CTX" in
        u:object_r:*) ;;
        *) CTX=u:object_r:system_file:s0 ;;
    esac

    mkdir -p "$DST"
    rm -f "$DST/$LIB_NAME" "$DST/$ORIG_NAME"

    cp "$SRC" "$DST/$ORIG_NAME"
    "$MODDIR/patch_sym" "$DST/$ORIG_NAME" "$LIB_NAME" "${LIB_NAME%.so}.sx"
    cp "$MODDIR/${LIB_NAME%.so}_shim.so" "$DST/$LIB_NAME"

    for f in "$DST/$LIB_NAME" "$DST/$ORIG_NAME"; do
        chown 0:0 "$f"
        chmod 0644 "$f"
        chcon "$CTX" "$f"
    done
    chcon u:object_r:system_file:s0 "$MODDIR/system" "$DST"
}

# Files from a previous boot's Magic Mount setup; recreated below if the
# device still needs them (keeps them in sync with OTA-updated originals).
rm -rf "$MODDIR/system/lib64"

# Pre-create /dev/btaddr and /dev/btlinkmode so the BT shim (bluetooth domain)
# can write to them. Need to exist before BT starts; post-fs-data.sh runs as
# root before any service.
touch /dev/btaddr
chown bluetooth:bluetooth /dev/btaddr
chmod 0644 /dev/btaddr
chcon u:object_r:bluetooth_data_file:s0 /dev/btaddr

touch /dev/btlinkmode
chown bluetooth:bluetooth /dev/btlinkmode
chmod 0644 /dev/btlinkmode
chcon u:object_r:bluetooth_data_file:s0 /dev/btlinkmode

APEX_LIB=/apex/com.android.btservices/lib64
APEX_LIB_LEGACY=/apex/com.android.bt/lib64

if [ -f "$APEX_LIB/libbluetooth_jni.so" ]; then
    setup_overlay "$APEX_LIB" libbluetooth_jni.so
elif [ -f "$APEX_LIB_LEGACY/libbluetooth_jni.so" ]; then
    setup_overlay "$APEX_LIB_LEGACY" libbluetooth_jni.so
# Qualcomm split-stack: JNI_OnLoad lives in a thin *_qti_jni.so wrapper, the
# CoD/Bond code stays in libbluetooth_qti.so (its DT_NEEDED dependency, left
# untouched — the shim locates and hooks it live in memory). Must be checked
# before the plain libbluetooth_qti.so branches below, since on these devices
# only the _jni wrapper may be bind-mounted, never the vendor lib itself.
elif [ -f /vendor/lib64/libbluetooth_qti_jni.so ]; then
    setup_overlay /vendor/lib64 libbluetooth_qti_jni.so
elif [ -f /system/lib64/libbluetooth_qti_jni.so ]; then
    setup_overlay /system/lib64 libbluetooth_qti_jni.so
elif [ -f /system/system_ext/lib64/libbluetooth_qti_jni.so ]; then
    setup_overlay /system/system_ext/lib64 libbluetooth_qti_jni.so
elif [ -f /vendor/lib64/libbluetooth_qti.so ]; then
    setup_overlay /vendor/lib64 libbluetooth_qti.so
elif [ -f /system/lib64/libbluetooth_qti.so ]; then
    setup_overlay /system/lib64 libbluetooth_qti.so
elif [ -f /system/system_ext/lib64/libbluetooth_qti.so ]; then
    setup_overlay /system/system_ext/lib64 libbluetooth_qti.so
# Non-APEX stack in /system (e.g. Android 9): the JNI entry point lives in
# libbluetooth_jni.so, which System.loadLibrary loads and whose JNI_OnLoad
# starts the shim. libbluetooth.so (the stack itself, where the hook targets
# live) has no JNI_OnLoad and is dlopen'ed later by classInitNative; the
# shim finds it via PLAIN_LIB_CANDIDATES and its retry thread.
elif [ -f /system/lib64/libbluetooth_jni.so ]; then
    setup_magic_mount libbluetooth_jni.so
fi
