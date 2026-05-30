/*
 * jni.c — JNI library loaded by Joy-Con Droid.
 *
 * getBluetoothAddressNative: reads MAC from /dev/btaddr written by the shim.
 */

#include "btaddr.h"

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