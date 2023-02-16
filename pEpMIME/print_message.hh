// This file is under GNU General Public License 3.0
// see LICENSE.txt

// Declarations for some helper functions to print pEpEngine's message struct to stderr

#ifndef PEP_MIME_PRINT_MESSAGE_HH
#define PEP_MIME_PRINT_MESSAGE_HH

#include "pEpMIME.hh"
#include <iostream>

namespace std
{
	ostream& operator<<(ostream&, struct tm const&);
	
	inline
	ostream& operator<<(ostream& o, struct tm const* t)
	{
		if(t)
		{
			return o << *t;
		}
		
		return o << "(NULL)";
	}
	
}


namespace pEpMIME
{

template<class T>
T out(const T& t) { return t; }

std::string out(char* s);

std::string out(pEp_identity* id);

std::string out(identity_list* idl);

std::string out(stringlist_t* sl);

std::string out(stringpair_list_t* spl);

void print_message(message* m);

} // end of namespace pEpMIME

#endif // PEP_MIME_PRINT_MESSAGE_HH
