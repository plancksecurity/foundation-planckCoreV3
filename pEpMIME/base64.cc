// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "base64.hxx"
#include <stdint.h>
#include <stdexcept>
#include "pEpMIME_internal.hh"

namespace pEpMIME
{

namespace base64 {

	const char* const b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	const int8_t values[256] = {
			//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
			__, __, __, __, __, __, __, __, __, SP, SP, __, SP, SP, __, __,  // 0x00 .. 0x0F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x10 .. 0x1F
			SP, __, __, __, __, __, __, __, __, __, __, 62, __, __, __, 63,  // 0x20 .. 0x2F
			52, 53, 54, 55, 56, 57, 58, 59, 60, 61, __, __, __, EQ, __, __,  // 0x30 .. 0x3F   0x3D = '='
			__,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  // 0x40 .. 0x4F
			15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, __, __, __, __, __,  // 0x50 .. 0x5F
			__, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  // 0x60 .. 0x6F
			41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, __, __, __, __, __,  // 0x70 .. 0x7F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x80 .. 0x8F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x90 .. 0x9F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xA0 .. 0xAF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xB0 .. 0xBF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xC0 .. 0xCF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xD0 .. 0xDF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xE0 .. 0xEF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xF0 .. 0xFF
		};


std::string decode(const std::string& input)
try{
	std::string ret;
	ret.reserve( (input.size()+3)/4 * 3 );
	auto out = std::back_inserter(ret);
	decode_iter(input.begin(), input.end(), out, infinity_end);
	return ret;
}
catch(const IllegalCharacter& ic)
{
	throw std::runtime_error("Illegal character (" + std::to_string( int(ic.c) ) + ") in base64-encoded string \"" + input + "\"" );
}


void encode(std::string& output, sv input, int line_length, sv delimiter)
{
	if(input.empty())
	{
		return;
	}
	
	typedef uint8_t U8;
	
	const unsigned triples = input.size()/3;
	const unsigned triples_per_line = unsigned(line_length) / 4u;
	const unsigned lines = ((input.size()+2)/3) / triples_per_line + 1;
	
	output.reserve( output.size() + (input.size()+2)/3 * 4  + lines*delimiter.size() );
	
	unsigned t = 0;
	const char* s = input.data();
	for(unsigned q=0; q<triples; ++q, ++t, s+=3)
	{
		if(t>triples_per_line)
		{
			output += delimiter;
			t=0;
		}
		
		const uint32_t u = U8(s[0])*65536 + U8(s[1])*256 + U8(s[2]);
		output += b64c[ (u>>18) & 63 ];
		output += b64c[ (u>>12) & 63 ];
		output += b64c[ (u>> 6) & 63 ];
		output += b64c[ (u    ) & 63 ];
	}
	
	if(t>triples_per_line)
	{
		output += delimiter;
	}
	
	switch(input.size() - triples*3)
	{
		case 2 :
			{
				const uint32_t u = U8(s[0])*65536 + U8(s[1])*256;
				output += b64c[ (u>>18) & 63 ];
				output += b64c[ (u>>12) & 63 ];
				output += b64c[ (u>> 6) & 63 ];
				output += '=';
				break;
			}
		case 1 :
			{
				const uint32_t u = U8(s[0])*65536;
				output += b64c[ (u>>18) & 63 ];
				output += b64c[ (u>>12) & 63 ];
				output += '=';
				output += '=';
				break;
			}
		case 0: break;
		default : throw std::logic_error("Internal error in base64_encode()!");
	}
	
	output += delimiter;
}


} // end of namespace pEpMIME::base64
} // end of namespace pEpMIME
