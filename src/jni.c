/*
 * jni.c — JNI library loaded by Joy-Con Droid.
 *
 * getBluetoothAddressNative: reads MAC from /dev/btaddr written by the shim.
 * getBluetoothLinkModeNative: reads the current BT link power mode from
 * /dev/btlinkmode written by the shim's Mode-Change hook — lets JCD avoid
 * sending HID reports while BTM is mid-negotiation of a Sniff Mode
 * transition.
 */

#include "btaddr.h"
#include "btlinkmode.h"

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

__attribute__((visibility("default")))
jstring Java_com_rdapps_gamepad_util_BluetoothCompanion_getBluetoothAddressNative(
    JNIEnv *env, jclass thiz)
{
    (void)thiz;

    int fd = open(BTADDR_PATH, O_RDONLY);
    if (fd < 0) return NULL;

    char buf[20] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return NULL;

    buf[strcspn(buf, "\n")] = '\0';
    return (*env)->NewStringUTF(env, buf);
}

/* Returns the current link mode (0=Active, 1=Hold, 2=Sniff, 3=Park, see
 * btlinkmode.h) or -1 if the device node is missing/unreadable (module not
 * installed, or no Mode-Change hook target found on this device). */
__attribute__((visibility("default")))
jint Java_com_rdapps_gamepad_util_BluetoothCompanion_getBluetoothLinkModeNative(
    JNIEnv *env, jclass thiz)
{
    (void)env;
    (void)thiz;

    int fd = open(BTLINKMODE_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[2] = {0};
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0 || buf[0] < '0' || buf[0] > '3') return -1;

    return buf[0] - '0';
}
