#ifndef PARSE_H
#define PARSE_H
#include <string>
#include <regex>
using namespace std;

class Parse
{
    string domain;
    string findRule;
    regex *rule{nullptr};
public:
    Parse(int argc, char** argv);
    static void checkArgc(int argc);
    const char *retnDomain();
    string sRetnDomain();
    void makeRule(string domain);
    regex *retRule();
};

#endif // PARSE_H
