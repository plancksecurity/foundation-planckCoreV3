// This file is under GNU General Public License 3.0
// see LICENSE.txt

// test program to "fuzz" libpEpMIME (and libetpan for comparison)

#include "pEpMIME.hh"
#include "../src/mime.h"
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>

void printhelpmessage(std::ostream& o)
{
	o << "Usage: fuzz {-p|-e} <example.eml> […]\n\n"
		"\t-p : use libpEpMIME as MIME parser\n"
		"\t-e : use libetpan as MIME parser\n"
		"\n";
}


std::string slurp(const std::string& filename)
{
    std::ifstream input(filename.c_str(), std::ios_base::binary);
    if(!input)
    {
        throw std::runtime_error("Cannot read file \"" + filename + "\"! ");
    }
    
    std::stringstream sstr;
    sstr << input.rdbuf();
    return sstr.str();
}


int main(int argc, char** argv)
{
	if(argc==1)
	{
		printhelpmessage(std::cerr);
		return 1;
	}
	
	const std::string argv1 = argv[1];
	if(argv1 == "-p")
	{
		// test with libpEpMIME
		for(int a=2; a<argc; ++a)
		{
			const std::string f = slurp(argv[a]);
			message* m = pEpMIME::parse_message(f.c_str(), f.size());
			free_message(m);
		}
		return 0;
	}else if(argv1 == "-e")
	{
		// test with libetpan
		for(int a=2; a<argc; ++a)
		{
			const std::string f = slurp(argv[a]);
			message* m = nullptr;
			bool has_pEp_msg = false;
			const PEP_STATUS status = mime_decode_message(f.c_str(), f.size(), &m, &has_pEp_msg);
			std::cerr << "Status: " << status << ". has_pEp_message=" << has_pEp_msg << ".\n";
			free_message(m);
		}
		return 0;
	}else if(argv1 == "-h" || argv1=="--help")
	{
		printhelpmessage(std::cout);
		return 0;
	}
	
	printhelpmessage(std::cerr);
	return 1;
}
