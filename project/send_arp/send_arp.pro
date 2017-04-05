TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += send_arp.cpp \
    mac.cpp \
    ip.cpp

HEADERS += \
    mac.h \
    ip.h
