/*
 * btaddr.c — reads the host Bluetooth MAC via JVM reflection and writes it
 * to /dev/btaddr for consumption by JCD (libjoycondroid_jni.so).
 *
 * Reflection chain:
 *   AdapterService.getAdapterService() → .mAdapterProperties → .mAddress (byte[6])
 *
 * Called once from shim.c:on_stack_ready(), which is triggered by the CoD
 * hook (cod.c) after the BT stack has completed HCI Read_BD_Addr. On some
 * stacks (e.g. Android 9, some Qualcomm devices) the first CoD write comes
 * before the Java side has stored the address, so mAddress is still null or
 * zeroed at that point. Such transient misses are retried from a background
 * thread (BTADDR_RETRY_INTERVAL_US, up to BTADDR_RETRY_MAX_ATTEMPTS); missing
 * methods/fields or an unwritable /dev/btaddr are permanent and not retried.
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
#include <pthread.h>

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

/* Outcome of one attempt. */
#define BTADDR_OK         0
#define BTADDR_TRANSIENT  1   /* not available yet — worth retrying */
#define BTADDR_PERMANENT  2   /* retrying cannot help */

#define BTADDR_RETRY_INTERVAL_US  (500 * 1000)
#define BTADDR_RETRY_MAX_ATTEMPTS 60          /* ~30 s */

/*
 * One read-and-write attempt. Errors are logged only if log_errors is set,
 * so the retry loop does not flood logcat with the same transient miss.
 */
#define FAIL(kind, ...) do { \
        if (log_errors || (kind) == BTADDR_PERMANENT) LOGE(__VA_ARGS__); \
        result = (kind); goto done; \
    } while (0)

static int try_write_bt_addr(int log_errors)
{
    JNIEnv *env = NULL;
    int attached = 0;
    int result = BTADDR_PERMANENT;

    if (!g_jvm || !g_adapter_service_cls) return BTADDR_PERMANENT;

    jint rc = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
            LOGE("write_bt_addr: AttachCurrentThread failed");
            return BTADDR_PERMANENT;
        }
        attached = 1;
    } else if (rc != JNI_OK || !env) {
        LOGE("write_bt_addr: GetEnv failed (%d)", rc);
        return BTADDR_PERMANENT;
    }

    /* Keeps local refs bounded when called repeatedly on an attached thread. */
    if ((*env)->PushLocalFrame(env, 16) != 0) {
        LOGE("write_bt_addr: PushLocalFrame failed");
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return BTADDR_PERMANENT;
    }

    jclass svcCls = g_adapter_service_cls;

    jmethodID getSvc = (*env)->GetStaticMethodID(env, svcCls, "getAdapterService",
        "()Lcom/android/bluetooth/btservice/AdapterService;");
    if (!getSvc) FAIL(BTADDR_PERMANENT, "write_bt_addr: getAdapterService not found");

    jobject svc = (*env)->CallStaticObjectMethod(env, svcCls, getSvc);
    if (!svc) FAIL(BTADDR_TRANSIENT, "write_bt_addr: getAdapterService returned null");

    jfieldID propsField = (*env)->GetFieldID(env, svcCls, "mAdapterProperties",
        "Lcom/android/bluetooth/btservice/AdapterProperties;");
    if (!propsField) FAIL(BTADDR_PERMANENT, "write_bt_addr: mAdapterProperties field not found");

    jobject props = (*env)->GetObjectField(env, svc, propsField);
    if (!props) FAIL(BTADDR_TRANSIENT, "write_bt_addr: mAdapterProperties is null");

    jclass propsCls = (*env)->GetObjectClass(env, props);
    jfieldID addrField = (*env)->GetFieldID(env, propsCls, "mAddress", "[B");
    if (!addrField) FAIL(BTADDR_PERMANENT, "write_bt_addr: mAddress field not found");

    jbyteArray addrArr = (jbyteArray)(*env)->GetObjectField(env, props, addrField);
    if (!addrArr || (*env)->GetArrayLength(env, addrArr) < 6)
        FAIL(BTADDR_TRANSIENT, "write_bt_addr: mAddress array missing or short");

    jbyte raw[6];
    (*env)->GetByteArrayRegion(env, addrArr, 0, 6, raw);
    if (!(raw[0] | raw[1] | raw[2] | raw[3] | raw[4] | raw[5]))
        FAIL(BTADDR_TRANSIENT, "write_bt_addr: mAddress is all zeros");

    char buf[20];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X\n",
             (uint8_t)raw[0], (uint8_t)raw[1], (uint8_t)raw[2],
             (uint8_t)raw[3], (uint8_t)raw[4], (uint8_t)raw[5]);

    int fd = open(BTADDR_PATH, O_WRONLY | O_TRUNC);
    if (fd < 0)
        FAIL(BTADDR_PERMANENT, "write_bt_addr: open(%s) failed (errno=%d)", BTADDR_PATH, errno);
    write(fd, buf, strlen(buf));
    close(fd);
    LOGI("write_bt_addr: wrote %02X:%02X:%02X:XX:XX:XX to %s",
         (uint8_t)raw[0], (uint8_t)raw[1], (uint8_t)raw[2], BTADDR_PATH);
    result = BTADDR_OK;

done:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
    return result;
}

#undef FAIL

static void *btaddr_retry_thread(void *arg)
{
    (void)arg;
    for (int attempt = 1; attempt <= BTADDR_RETRY_MAX_ATTEMPTS; attempt++) {
        usleep(BTADDR_RETRY_INTERVAL_US);
        int last = attempt == BTADDR_RETRY_MAX_ATTEMPTS;
        int r = try_write_bt_addr(last);
        if (r == BTADDR_OK) {
            LOGI("write_bt_addr: succeeded on retry %d", attempt);
            return NULL;
        }
        if (r == BTADDR_PERMANENT) return NULL;
    }
    LOGE("write_bt_addr: address still unavailable after retry — giving up");
    return NULL;
}

void write_bt_addr(void)
{
    if (try_write_bt_addr(1) != BTADDR_TRANSIENT) return;

    LOGI("write_bt_addr: address not available yet, retrying in background");
    pthread_t t;
    if (pthread_create(&t, NULL, btaddr_retry_thread, NULL) != 0) {
        LOGE("write_bt_addr: pthread_create failed (errno=%d)", errno);
        return;
    }
    pthread_detach(t);
}
