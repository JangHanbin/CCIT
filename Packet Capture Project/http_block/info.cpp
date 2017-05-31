#include "info.h"
#include "errhandling.h"
#include <cstring>

Info::Info(int argc, char* argv[])
{
    checkArg(argc); //check argument
    host=argv[1];
    makeRule();
    blockString=argv[2];
    blockStringLen=blockString.length();
}

Info::~Info()
{
    delete(rule);
}

void Info::usage()
{
    errorRetn("Usage : http_block <Host> <Block String>");
}

void Info::checkArg(int argc)
{
    if(argc!=3)
        usage();
}

void Info::makeRule()
{
    std::string findRule=host;

    rule = new std::regex("("+findRule+")(.*)");


}
