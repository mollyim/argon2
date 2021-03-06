LOCAL_PATH := $(call my-dir)
ARGON2_DIR := $(LOCAL_PATH)/../../../phc-winner-argon2

include $(CLEAR_VARS)

LOCAL_MODULE     := argon2
LOCAL_C_INCLUDES := $(ARGON2_DIR)/include/
LOCAL_CFLAGS     += -Wall
ifeq ($(APP_OPTIM),release)
LOCAL_LDLIBS     += -Wl,--build-id=none
endif

LOCAL_SRC_FILES := org_signal_argon2_Argon2Native.c \
                   $(ARGON2_DIR)/src/blake2/blake2b.c \
                   $(ARGON2_DIR)/src/argon2.c \
                   $(ARGON2_DIR)/src/core.c \
                   $(ARGON2_DIR)/src/encoding.c \
                   $(ARGON2_DIR)/src/genkat.c \
                   $(ARGON2_DIR)/src/ref.c \
                   $(ARGON2_DIR)/src/thread.c

include $(BUILD_SHARED_LIBRARY)
