TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += main.cpp \
    ip.cpp \
    mac.cpp \
    param.cpp \
    getmyinfo.cpp \
    printdata.cpp

HEADERS += \
    param.h \
    mac.h \
    ip.h \
    getmyinfo.h \
    printdata.h
