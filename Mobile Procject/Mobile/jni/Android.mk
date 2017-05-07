LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := mobile-jni
LOCAL_SRC_FILES := getmyinfo.h getmyinfo.cpp ip.h ip.cpp mac.h mac.cpp info.h info.cpp main.cpp
LOCAL_LDLIBS :=-lpcap
include $(BUILD_SHARED_LIBRARY)
