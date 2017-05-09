#include "parse.h"
#include <iostream>

void Parse::checkArgc(int argc)
{
    if(argc!=2)
    {
        cout<<"Usage : netfilter_block <domain>"<<endl;
        exit(1);
    }
}

Parse::Parse(int argc, char **argv)
{
    checkArgc(argc);
    this->domain=argv[1];
    int location=this->domain.find("www.");
    if(location!=-1)                      //if find www.
        this->domain=this->domain.substr(this->domain.find(".")+1,this->domain.length());//get rid of www.

    makeRule(this->domain);
}

const char* Parse::retnDomain() {return this->domain.c_str();}

string Parse::sRetnDomain(){return this->domain;}

void Parse::makeRule(string domain)
{
    this->findRule="(";
    this->findRule+=domain;
    this->findRule+=")(.*)";

    rule = new regex(findRule);

}

regex* Parse::retRule() {return this->rule;}
