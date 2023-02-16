// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "base64.hh"
#include <stdint.h>
#include <stdexcept>
#include "pEpMIME_internal.hh"
#include "../src/pEp_string.h"

namespace pEpMIME
{

namespace base64 {

static constexpr const int8_t __ = -1; // invalid char -> exception!
static constexpr const int8_t SP = -2; // space char -> ignore
static constexpr const int8_t EQ = -3; // '=' char -> special handling of EOF

// encoding alphabet
extern const char* const b64c; 

// decoding array
extern const int8_t values[256];


	struct IllegalCharacter
	{
		char c;
	};
	
	struct OutputOverflow {};
	
	template<class Iter>
	unsigned fetch(Iter& s, Iter end)
	{
		while( s != end)
		{
			const int8_t sc =  values[ uint8_t(*s) ];
			if(sc==-1) throw IllegalCharacter{*s};
			++s;
			if(sc>=0)
			{
				return uint8_t(sc);
			}else{
				if(sc==EQ) { return 255; }
			}
		}
		
		return 255;
	}

	// use with potentially "infinite" output containers, e.g. together with back_insert_iterator<>
	struct InfinityIterator {};
	static InfinityIterator infinity_end{};
	
	template<class OutIter>
	inline
	bool operator==(OutIter out, InfinityIterator ii)
	{
		return false;
	}

//
// |-+-+-+-+-+-|-+-+-+-+-+-|-+-+-+-+-+-|-+-+-+-+-+-|
// |     u0    |     u1    |     u2    |     u3    |
// |           |           |           |           |
// |5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|
// |-+-+-+-+-+-|-+-+-+-+-+-|-+-+-+-+-+-|-+-+-+-+-+-|
// |7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
// |-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|
// |               |               |               |
// |    Byte 0     |    Byte 1     |    Byte 2     |
// |-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|
//

// decodes base64-encoded 'input', skip whitespaces, throw if illegal character found in string
template<class InIter, class OutIter, class OutIter2>
void decode_iter(InIter begin, InIter end, OutIter& out, OutIter2 out_end)
{
	while(begin != end)
	{
		const uint8_t u0 = fetch(begin, end);
		if(u0==255)
			break; // end of input data
		
		const uint8_t u1 = fetch(begin, end);
		const uint8_t u2 = fetch(begin, end);
		const uint8_t u3 = fetch(begin, end);
		
		if(u1!=255)
		{
			if(out == out_end) throw OutputOverflow{};
			*out = char( (u0 << 2) | (u1 >> 4) );
			++out; 
		}
		
		if(u2!=255)
		{
			if(out == out_end) throw OutputOverflow{};
			*out = char( (u1 << 4) | (u2 >> 2) );
			++out;
		}
		
		if(u3!=255)
		{
			if(out == out_end) throw OutputOverflow{};
			*out = char( (u2 << 6) | (u3     ) );
			++out;
		}
	}
}

} // end of namespace pEpMIME::base64
} // end of namespace pEpMIME
