#ifndef PRINTDATA_H
#define PRINTDATA_H
#include <iostream>
#include <iomanip>

using namespace std;

void printLine();


void printByHexData(u_int8_t *printArr, int length);


void printByMAC(u_int8_t *printArr,int length);


#endif // PRINTDATA_H
