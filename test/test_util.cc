#include "pEpEngine_test.h"
#include <fstream>
#include <sstream>
#include <stdexcept>

std::string slurp(const std::string& filename)
{
	std::ifstream input(filename.c_str());
	if(!input)
	{
		throw std::runtime_error("Cannot read file \"" + filename + "\"! ");
	}
	
	std::stringstream sstr;
	sstr << input.rdbuf();
	return sstr.str();
}
