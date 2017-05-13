#include "regexmethod.h"
#include <regex>
#include <iostream>

using namespace std;

bool findAndFixStirng(regex rg, uint8_t* data,bool flag,string reString)
{

    cmatch m;
    string str=(char*)data;


    uint8_t* position;
    if(!regex_search((char*)data,m,rg))
        return false;
    else
    {
        while(regex_search((char*)data,m,rg))
        {
            if(flag)
            {

                position=data+m.position();
                memcpy(position,reString.c_str(),reString.length());

            }
        }

        return true;
    }

}

bool fixEncoding(regex rg, uint8_t *data, string reString)
{
    cmatch m;
    if(regex_search((char*)data,m,rg))
    {
        uint8_t* findLocation=data+m.position();
        memcpy(findLocation,reString.c_str(),reString.length()); //replace string without null
        memset(findLocation+reString.length(),' ',m[0].length()-reString.length());

        return true;

    }else
        return false;

}
