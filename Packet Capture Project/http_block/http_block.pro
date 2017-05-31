TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    info.cpp \
    calchecksum.cpp \
    errhandling.cpp \
    printdata.cpp \
    jpcaplib.cpp \
    regexmethod.cpp

HEADERS += \
    info.h \
    calchecksum.h \
    errhandling.h \
    printdata.h \
    jpcaplib.h \
    regexmethod.h

DISTFILES += \
    http_block.pro.user
