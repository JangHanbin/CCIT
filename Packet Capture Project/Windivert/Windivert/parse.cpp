#include "parse.h"
#include <iostream>

using namespace std;


Parse::Parse(int argc, char* argv[])
{

	if (!(argc != 2 || argc != 3))
	{
		usage();
		exit(1);
	}
	
	if (argc == 2)
		host = argv[1];
	else if (argc==3&&strcmp(argv[1],"-f")==0)
	{
		fileName = argv[2];
		isFile = true;
		
		
	}
	else {
		usage();
		exit(1);
	}

}

void Parse::usage()
{
	cout<<"Usage : Windivert <host>" << endl;
	cout << "Usage : Windivert <-f> <File Name>" << endl;
	
}

char * Parse::retnFileName()
{
	return this->fileName;
}

char * Parse::retnHost()
{
	return this->host;
}

bool Parse::retnIsFile()
{
	return this->isFile;
}

