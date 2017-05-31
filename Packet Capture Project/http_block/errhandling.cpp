#include "errhandling.h"
#include <iostream>
#include <cstring>

void errorRetn(std::string content)
{
    std::cout<<content.c_str()<<std::endl;
    exit(1);

}
