# --- NDK ------------------------------------------------------------------
NDK_VERSION = 27.3.13750724
NDK_DIR    ?= $(ANDROID_HOME)/ndk/$(NDK_VERSION)
NDK_BIN     = $(NDK_DIR)/toolchains/llvm/prebuilt/linux-x86_64/bin
NDK_CC      = $(NDK_BIN)/aarch64-linux-android33-clang
NDK_STRIP   = $(NDK_BIN)/llvm-strip
NDK_CFLAGS  = -fPIC -O2 -Wl,--hash-style=gnu

# --- Android SDK ----------------------------------------------------------
BUILD_TOOLS_VERSION = 37.0.0
PLATFORM_VERSION    = 37.0
SDKMANAGER          = $(ANDROID_HOME)/cmdline-tools/latest/bin/sdkmanager
BUILD_TOOLS         = $(ANDROID_HOME)/build-tools/$(BUILD_TOOLS_VERSION)
ANDROID_JAR         = $(ANDROID_HOME)/platforms/android-$(PLATFORM_VERSION)/android.jar
AAPT                = $(BUILD_TOOLS)/aapt
ZIPALIGN            = $(BUILD_TOOLS)/zipalign

# --- JDK ------------------------------------------------------------------
JARSIGNER_CMD := $(shell command -v jarsigner 2>/dev/null)
KEYTOOL_CMD   := $(shell command -v keytool 2>/dev/null)
JARSIGNER      = $(if $(JARSIGNER_CMD),$(JARSIGNER_CMD),jarsigner-missing)
KEYTOOL        = $(if $(KEYTOOL_CMD),$(KEYTOOL_CMD),keytool-missing)

# --- Outputs --------------------------------------------------------------
BUILD   = build
JNI     = $(BUILD)/libjoycondroid_jni.so
PATCHER = $(BUILD)/patch_sym
ZIP     = $(BUILD)/JoyConDroidCompanion.zip

# --- Shim -----------------------------------------------------------------
SHIM_SRCS = src/shim.c src/cod.c src/bond.c src/bond_setter_scan.c src/btaddr.c
# One variant per BT library (APEX / pre-APEX / QTI / QTI split-stack).
SHIMS     = $(BUILD)/libbluetooth_jni_shim.so \
            $(BUILD)/libbluetooth_shim.so \
            $(BUILD)/libbluetooth_qti_shim.so \
            $(BUILD)/libbluetooth_qti_jni_shim.so

# --- RRO ------------------------------------------------------------------
RRO_APK_NAME   = com.github.teamjcd.joycondroidcompanion.rro.hid
RRO_ALIAS     ?= jcdcrro
RRO_STOREPASS ?= jcdcrro
RRO_KEYPASS   ?= jcdcrro
RRO_KEYSTORE   = $(BUILD)/rro.keystore
RRO_APK        = $(BUILD)/$(RRO_APK_NAME).apk

# --- Module ---------------------------------------------------------------
MODULE_FILES = module.prop post-fs-data.sh service.sh sepolicy.rule \
               META-INF/com/google/android/update-binary \
               META-INF/com/google/android/updater-script

.PHONY: all zip sdk clean jarsigner-missing keytool-missing

# --- User-facing targets --------------------------------------------------
all: $(SHIMS) $(JNI) $(PATCHER) $(RRO_APK)

sdk: | $(SDKMANAGER)
	$(SDKMANAGER) \
	    "ndk;$(NDK_VERSION)" \
	    "build-tools;$(BUILD_TOOLS_VERSION)" \
	    "platforms;android-$(PLATFORM_VERSION)"

zip: all $(MODULE_FILES) | $(BUILD)
	rm -f $(ZIP)
	mkdir -p $(BUILD)/system/vendor/overlay/$(RRO_APK_NAME)
	cp $(RRO_APK) $(BUILD)/system/vendor/overlay/$(RRO_APK_NAME)/$(RRO_APK_NAME).apk
	cd $(BUILD) && zip $(abspath $(ZIP)) \
	    $(notdir $(SHIMS) $(JNI) $(PATCHER)) \
	    system/vendor/overlay/$(RRO_APK_NAME)/$(RRO_APK_NAME).apk
	zip $(ZIP) $(MODULE_FILES)

clean:
	rm -rf build

# --- Tool checks ----------------------------------------------------------
$(NDK_CC) $(NDK_STRIP):
	$(error NDK $(NDK_VERSION) not found. Run: make sdk)

$(ANDROID_JAR):
	$(error platform $(PLATFORM_VERSION) not found. Run: make sdk)

$(SDKMANAGER):
	$(error Android command-line tools not found. Install Android Studio or the standalone SDK tools.)

$(AAPT) $(ZIPALIGN):
	$(error build-tools $(BUILD_TOOLS_VERSION) not found. Run: make sdk)

jarsigner-missing:
	$(error jarsigner not found. Install a JDK and ensure it is on PATH.)

keytool-missing:
	$(error keytool not found. Install a JDK and ensure it is on PATH.)

# --- Build targets --------------------------------------------------------
$(BUILD):
	mkdir -p $@

# $(call shim-variant,SUFFIX)
# Builds libbluetooth$(SUFFIX)_shim.so (SONAME libbluetooth$(SUFFIX).so) and
# a link-time stub that injects DT_NEEDED: libbluetooth$(SUFFIX)_orig.so.
define shim-variant
$(BUILD)/libbluetooth$(1)_orig_stub.so: src/stub.c | $(NDK_CC) $(BUILD)
	$(NDK_CC) -shared $(NDK_CFLAGS) -Wl,-soname,libbluetooth$(1)_orig.so -o $$@ $$<

$(BUILD)/libbluetooth$(1)_shim.so: $(SHIM_SRCS) $(BUILD)/libbluetooth$(1)_orig_stub.so | $(NDK_CC) $(NDK_STRIP) $(BUILD)
	$(NDK_CC) -shared $(NDK_CFLAGS) -nostdlib \
	    -Wl,-soname,libbluetooth$(1).so \
	    -Wl,--no-as-needed -L$(BUILD) -l:libbluetooth$(1)_orig_stub.so -llog \
	    -o $$@ $(SHIM_SRCS)
	$(NDK_STRIP) $$@
endef

$(eval $(call shim-variant,_jni))
$(eval $(call shim-variant,))
$(eval $(call shim-variant,_qti))
$(eval $(call shim-variant,_qti_jni))

# JNI library for Joy-Con Droid — Bionic libc.so DT_NEEDED added automatically.
$(JNI): src/jni.c | $(NDK_CC) $(NDK_STRIP) $(BUILD)
	$(NDK_CC) -shared $(NDK_CFLAGS) -Wl,-soname,libjoycondroid_jni.so -o $@ $<
	$(NDK_STRIP) $@

# Patcher: statically linked host binary, runs as root on the device.
$(PATCHER): patch_sym.c | $(NDK_CC) $(NDK_STRIP) $(BUILD)
	$(NDK_CC) -static -O2 -o $@ $<
	$(NDK_STRIP) $@

$(RRO_APK): rro/AndroidManifest.xml rro/res/values/bools.xml | $(AAPT) $(ZIPALIGN) $(ANDROID_JAR) $(JARSIGNER) $(KEYTOOL) $(BUILD)
	$(AAPT) package -M rro/AndroidManifest.xml -S rro/res/ \
	    -I "$(ANDROID_JAR)" -F $(BUILD)/overlay_unsigned.apk
	if [ -n "$$RRO_KEYSTORE_B64" ]; then \
	    printf '%s' "$$RRO_KEYSTORE_B64" | base64 -d > $(RRO_KEYSTORE); \
	else \
	    rm -f $(RRO_KEYSTORE); \
	    $(KEYTOOL) -genkeypair -noprompt \
	        -keystore $(RRO_KEYSTORE) \
	        -storepass "$(RRO_STOREPASS)" -keypass "$(RRO_KEYPASS)" \
	        -alias "$(RRO_ALIAS)" \
	        -dname "O=Unknown" \
	        -keyalg RSA -keysize 2048 -validity 10000; \
	fi
	$(JARSIGNER) -keystore $(RRO_KEYSTORE) \
	    -storepass "$(RRO_STOREPASS)" -keypass "$(RRO_KEYPASS)" \
	    $(BUILD)/overlay_unsigned.apk "$(RRO_ALIAS)"
	$(ZIPALIGN) -f 4 $(BUILD)/overlay_unsigned.apk $@
