#pragma once

#include <fstream>

class Parse
{

	char *fileName=nullptr;
	char *host=nullptr;
	bool isFile = false;

public:
	Parse(int argc, char* argv[]);
	void usage();
	char* retnFileName();
	char* retnHost();
	bool retnIsFile();

};