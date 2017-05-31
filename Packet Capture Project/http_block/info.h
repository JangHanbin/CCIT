#ifndef INFO_H
#define INFO_H

#include <regex>
#include <cstring>

class Info
{
public:
    Info(int argc, char *argv[]);
    ~Info();
    char* host;
    std::string blockString;
    int blockStringLen;
    std::regex* rule{nullptr};
    uint32_t cSeq;              //Client Seq num(Server Ack num)
    uint32_t sSeq;              //Server Seq num(client Ack num)
    void usage();
    void checkArg(int argc);
    void makeRule();
};

#endif // INFO_H
