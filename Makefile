NDK_VERSION = 30.0.14904198
NDK_DIR    ?= $(ANDROID_HOME)/ndk/$(NDK_VERSION)
NDK_BIN    = $(NDK_DIR)/toolchains/llvm/prebuilt/linux-x86_64/bin
NDK_CC     = $(NDK_BIN)/aarch64-linux-android33-clang
NDK_STRIP  = $(NDK_BIN)/llvm-strip

NDK_CFLAGS = -fPIC -O2 -Wl,--hash-style=gnu

BUILD = build

JNI     = $(BUILD)/libjoycondroid_jni.so
PATCHER = $(BUILD)/patch_sym
ZIP     = $(BUILD)/JoyConDroidCompanion.zip

SHIM_SRCS = src/shim.c src/cod.c src/bond.c src/btaddr.c

# One shim per BT library variant (APEX/pre-APEX/QTI).
SHIMS = $(BUILD)/libbluetooth_jni_shim.so \
        $(BUILD)/libbluetooth_shim.so \
        $(BUILD)/libbluetooth_qti_shim.so

MODULE_FILES = module.prop post-fs-data.sh service.sh sepolicy.rule \
               META-INF/com/google/android/update-binary \
               META-INF/com/google/android/updater-script

.PHONY: all zip ndk clean

all: $(SHIMS) $(JNI) $(PATCHER)

ndk:
	$(ANDROID_HOME)/cmdline-tools/latest/bin/sdkmanager "ndk;$(NDK_VERSION)"

zip: all $(MODULE_FILES) | $(BUILD)
	rm -f $(ZIP)
	cd $(BUILD) && zip $(abspath $(ZIP)) \
	    $(notdir $(SHIMS)) libjoycondroid_jni.so patch_sym
	zip $(ZIP) $(MODULE_FILES)

$(NDK_CC):
	$(error NDK not found at $(NDK_DIR). Run: make ndk)

$(BUILD):
	mkdir -p $@

# $(call shim-variant,SUFFIX)
# Builds libbluetooth$(SUFFIX)_shim.so (SONAME libbluetooth$(SUFFIX).so) and
# a link-time stub that injects DT_NEEDED: libbluetooth$(SUFFIX)_orig.so.
define shim-variant
$(BUILD)/libbluetooth$(1)_orig_stub.so: src/stub.c | $(BUILD)
	$(NDK_CC) -shared $(NDK_CFLAGS) -Wl,-soname,libbluetooth$(1)_orig.so -o $$@ $$<

$(BUILD)/libbluetooth$(1)_shim.so: $(SHIM_SRCS) $(BUILD)/libbluetooth$(1)_orig_stub.so | $(BUILD)
	$(NDK_CC) -shared $(NDK_CFLAGS) -nostdlib \
	    -Wl,-soname,libbluetooth$(1).so \
	    -Wl,--no-as-needed -L$(BUILD) -l:libbluetooth$(1)_orig_stub.so -llog \
	    -o $$@ $(SHIM_SRCS)
	$(NDK_STRIP) $$@
endef

$(eval $(call shim-variant,_jni))
$(eval $(call shim-variant,))
$(eval $(call shim-variant,_qti))

# JNI library for Joy-Con Droid — Bionic libc.so DT_NEEDED added automatically.
$(JNI): src/jni.c | $(BUILD)
	$(NDK_CC) -shared $(NDK_CFLAGS) -Wl,-soname,libjoycondroid_jni.so -o $@ $<
	$(NDK_STRIP) $@

# Patcher: statically linked host binary, runs as root on the device.
$(PATCHER): patch_sym.c | $(BUILD)
	$(NDK_CC) -static -O2 -o $@ $<
	$(NDK_STRIP) $@

clean:
	rm -rf build