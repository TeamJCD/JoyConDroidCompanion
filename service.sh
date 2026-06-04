#!/system/bin/sh
MODDIR="${0%/*}"

APP_DIR=$(find /data/app -maxdepth 3 -type d \
    -name "com.rdapps.gamepad-*" 2>/dev/null | head -1)
[ -z "$APP_DIR" ] && exit 0

APP_LIB="$APP_DIR/lib/arm64"
mkdir -p "$APP_LIB"
cp "$MODDIR/libjoycondroid_jni.so" "$APP_LIB/libjoycondroid_jni.so"
chmod 755 "$APP_LIB/libjoycondroid_jni.so"
chcon u:object_r:apk_data_file:s0 "$APP_LIB/libjoycondroid_jni.so"
