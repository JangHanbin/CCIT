#ifndef PARSE_H
#define PARSE_H

#include <string>
#include <regex>
using namespace std;

class Parse
{
    string findString;
    string modifyString;
    string findRule;
    char* findChar;
    char* modifyChar;
    int findLen;
    int modifyLen;
    regex *rule{nullptr};
    static regex *encodingRule;

public:
    Parse(int argc, char** argv);
    static void usage();
    void checkArgc(int argc, char **argv);
    void makeRule(string domain);
    regex *retRule();
    regex* retEncodingRule();
    string retModifyString();
    string retFindString();
    void allocPacket(uint32_t length);
    uint8_t* packet;
    uint32_t packetLen;

};

#endif // PARSE_H
