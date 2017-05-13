TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
SOURCES += main.cpp \
    parse.cpp \
    printdata.cpp \
    regexmethod.cpp \
    calchecksum.cpp

HEADERS += \
    parse.h \
    printdata.h \
    regexmethod.h \
    calchecksum.h
