#include "parse.h"
#include <iostream>

regex* Parse::encodingRule=new regex{"(Accept-Encoding:)(.*)"};

Parse::Parse(int argc, char **argv)
{
    checkArgc(argc,argv);

    this->findChar=argv[1];
    this->modifyChar=argv[2];
}

void Parse::usage()
{

    cout<<"Usage : netfilter_modify <find string> <modify string>"<<endl;
    cout<<"Must be same len string & string"<<endl;
    exit(1);
}

void Parse::checkArgc(int argc,char** argv)
{

    if(argc!=3)
        usage();

    this->findString=argv[1];
    this->modifyString=argv[2];
    this->findLen=this->findString.length();
    this->modifyLen=this->modifyString.length();

    if(findLen!=modifyLen)
        usage();

    makeRule(findString);
}

void Parse::makeRule(string name)
{
    this->findRule="(";
    this->findRule+=name;
    this->findRule+=")(.*)";

    rule = new regex(findRule);

}

regex* Parse::retRule() {return this->rule;}

regex *Parse::retEncodingRule(){ return this->encodingRule;}

string Parse::retModifyString(){return this->modifyString;}

string Parse::retFindString(){return this->findString;}

void Parse::allocPacket(uint32_t length)
{
    this->packetLen=length;
    this->packet=new uint8_t[this->packetLen];
}



