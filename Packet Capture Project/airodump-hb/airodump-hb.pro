TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS+= -lpcap
SOURCES += main.cpp \
    apinfo.cpp \
    jpcaplib.cpp \
    printdata.cpp \
    mac.cpp \
    stationinfo.cpp

HEADERS += \
    apinfo.h \
    jpcaplib.h \
    printdata.h \
    ieee802.h \
    mac.h \
    stationinfo.h
