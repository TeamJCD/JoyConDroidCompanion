/*
 * btaddr.c — reads the host Bluetooth MAC via JVM reflection and writes it
 * to /dev/btaddr for consumption by JCD (libjoycondroid_jni.so).
 *
 * Reflection chain:
 *   AdapterService.getAdapterService() → .mAdapterProperties → .mAddress (byte[6])
 *
 * Called once from shim.c:on_stack_ready(), which is triggered by hook_cod
 * after the BT stack has completed HCI Read_BD_Addr and the MAC is available.
 *
 * FindClass only resolves app classes when called from the main thread (app
 * classloader).  btaddr_init() is called from JNI_OnLoad on the main thread
 * and saves a GlobalRef; write_bt_addr() uses it from the hook thread.
 */

#include "shim.h"
#include "btaddr.h"

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

static jclass g_adapter_service_cls = NULL;

void btaddr_init(JNIEnv *env)
{
    jclass local = (*env)->FindClass(env,
        "com/android/bluetooth/btservice/AdapterService");
    if (!local) {
        LOGE("btaddr_init: AdapterService class not found");
        return;
    }
    g_adapter_service_cls = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
}

void write_bt_addr(void)
{
    JNIEnv *env = NULL;
    int attached = 0;

    if (!g_jvm || !g_adapter_service_cls) return;

    jint rc = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
            LOGE("write_bt_addr: AttachCurrentThread failed");
            return;
        }
        attached = 1;
    } else if (rc != JNI_OK || !env) {
        LOGE("write_bt_addr: GetEnv failed (%d)", rc);
        return;
    }

    jclass svcCls = g_adapter_service_cls;

    jmethodID getSvc = (*env)->GetStaticMethodID(env, svcCls, "getAdapterService",
        "()Lcom/android/bluetooth/btservice/AdapterService;");
    if (!getSvc) { LOGE("write_bt_addr: getAdapterService not found"); goto done; }

    jobject svc = (*env)->CallStaticObjectMethod(env, svcCls, getSvc);
    if (!svc) { LOGE("write_bt_addr: getAdapterService returned null"); goto done; }

    jfieldID propsField = (*env)->GetFieldID(env, svcCls, "mAdapterProperties",
        "Lcom/android/bluetooth/btservice/AdapterProperties;");
    if (!propsField) { LOGE("write_bt_addr: mAdapterProperties field not found"); goto done; }

    jobject props = (*env)->GetObjectField(env, svc, propsField);
    if (!props) { LOGE("write_bt_addr: mAdapterProperties is null"); goto done; }

    jclass propsCls = (*env)->GetObjectClass(env, props);
    jfieldID addrField = (*env)->GetFieldID(env, propsCls, "mAddress", "[B");
    if (!addrField) { LOGE("write_bt_addr: mAddress field not found"); goto done; }

    jbyteArray addrArr = (jbyteArray)(*env)->GetObjectField(env, props, addrField);
    if (!addrArr || (*env)->GetArrayLength(env, addrArr) < 6) {
        LOGE("write_bt_addr: mAddress array missing or short");
        goto done;
    }

    jbyte raw[6];
    (*env)->GetByteArrayRegion(env, addrArr, 0, 6, raw);

    char buf[20];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X\n",
             (uint8_t)raw[0], (uint8_t)raw[1], (uint8_t)raw[2],
             (uint8_t)raw[3], (uint8_t)raw[4], (uint8_t)raw[5]);

    int fd = open(BTADDR_PATH, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        LOGE("write_bt_addr: open(%s) failed (errno=%d)", BTADDR_PATH, errno);
        goto done;
    }
    write(fd, buf, strlen(buf));
    close(fd);
    LOGI("write_bt_addr: wrote %s to %s", buf, BTADDR_PATH);

done:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
}