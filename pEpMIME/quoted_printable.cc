// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "quoted_printable.hxx"
#include <stdint.h>
#include <stdexcept>

namespace pEpMIME
{
namespace qp
{
	const int8_t values[256] = {
			//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x00 .. 0x0F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x10 .. 0x1F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x20 .. 0x2F
			 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, __, __, __, __, __, __,  // 0x30 .. 0x3F   0x3D = '='
			__, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __,  // 0x40 .. 0x4F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x50 .. 0x5F
			__, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __,  // 0x60 .. 0x6F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x70 .. 0x7F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x80 .. 0x8F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x90 .. 0x9F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xA0 .. 0xAF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xB0 .. 0xBF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xC0 .. 0xCF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xD0 .. 0xDF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xE0 .. 0xEF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xF0 .. 0xFF
		};

    const char* const hexdigit = "0123456789ABCDEF";

	static const int8_t OK = Word; // allowed in Q-encoded "encoded-word"s (most restricted charset from RFC 2047 5. (3) )
	static const int8_t TX = Text; // allowed in Q-encoded texts
	const int8_t allowed[256] = {
			//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x00 .. 0x0F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x10 .. 0x1F
			__, OK, __, TX, TX, TX, TX, __, __, __, OK, OK, __, OK, TX, OK,  // 0x20 .. 0x2F  ! * + - /
			OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, TX, __, __, __, __, __,  // 0x30 .. 0x3F   0x3D = '='
			__, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK,  // 0x40 .. 0x4F
			OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, __, __, __, __, __,  // 0x50 .. 0x5F
			__, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK,  // 0x60 .. 0x6F
			OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, OK, __, __, __, __, __,  // 0x70 .. 0x7F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x80 .. 0x8F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0x90 .. 0x9F
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xA0 .. 0xAF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xB0 .. 0xBF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xC0 .. 0xCF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xD0 .. 0xDF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xE0 .. 0xEF
			__, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __,  // 0xF0 .. 0xFF
		};


// decodes "quoted printable"-encoded 'input', throw if illegal character found in string
std::string decode(sv input)
try
{
    std::string ret;
    ret.reserve( input.size() );
    auto out = std::back_inserter(ret);
    decode_iter(input.begin(), input.end(), out, infinity_end);
    return ret;
}
catch(const UnexpectedEnd& ue)
{
    throw std::runtime_error("Unexpected end of qp-encoded string \"" + input + "\"");
}
catch(const IllegalHexSequence& ihs)
{
    throw std::runtime_error( std::string("Illegal hex sequence “=") + ihs.high + ihs.low + "” in qp-encoded string \"" + input + "\"");
}


// decodes "quoted printable"-encoded header line, throw if illegal character found in string
// means: no "soft line breaks", but special handling of underscores.
// TODO: use decode_iter<> here, too? Humm, don't know...
std::string decode_header(sv input)
{
    std::string ret;
    ret.reserve( input.size() );
    
    const char*       c   = input.data();
    const char* const end = c + input.size();
    
    while(c < end)
    {
        const char ch=*c;
        switch(ch)
        {
            case '=':
            {
                ++c;
                if(c+1>=end)
                {
                    // throw std::runtime_error("Unexpected end of qp-encoded string!");
                    ret += '=';
                    continue;
                }
                
                const char high = *c;
                ++c;
                const char low  = *c;
                try{
                    ret += char(from_hex(high, low));
                }catch(const IllegalHexSequence& h)
                {
                    ret += '=';
                    ret += high;
                    ret += low;
                }
                break;
            }
            
            case '_':
                ret += ' ';
                break;
            
            default:
                ret += ch;
        }
        ++c;
    }
    
    return ret;
}


std::string encode(sv input)
{
    std::string ret;
    ret.reserve( input.size() );
    const unsigned max_u = input.size() - 1;
    
    unsigned line_length = 0;
    for(std::size_t u=0; u<input.size(); ++u)
    {
        unsigned char c = input[u];
        if(c == '\r')
        {
            if(u<max_u && input[u+1]=='\n') // hard line break
            {
                ret += "\r\n";
                ++u;
                line_length = 0;
            }else{
                ret += "=0D";
                line_length+=3;
            }
        }else if(c == '=' || c<' ' || c>126)
        {
            char escape[] = { '=', hexdigit[c>>4], hexdigit[c & 0xF] };
            ret.append(escape, escape+3);
            line_length+=3;
        }else{
            ret += c;
            ++line_length;
        }
        
        if(line_length >= MaxLineLength && u<max_u)
        {
            ret += "=\r\n";
            line_length = 0;
        }
    }
    
    return ret;
}


std::string encode_header(sv name, sv value, HeaderType type)
{
    std::string ret{ (name.size() ? std::string(name) + ": " : std::string() ) + "=?UTF-8?Q?"};
    ret.reserve( name.size() + value.size() + 16);
    static const unsigned max_line_len = MaxLineLength - 2; // subtract 2 chars for QP footer
    
    unsigned line_length = ret.size();
    for(std::size_t u=0; u<value.size(); ++u)
    {
        if(line_length > max_line_len)
        {
            ret += "?=\r\n =?UTF-8?Q?";
            line_length = 10;
        }
        
        const unsigned char c = value[u];
        if(allowed[c] >= type)
        {
            ret += char(c);
            ++line_length;
        }else if(c==' ')
        {
            ret += '_';
            ++line_length;
        }else
        {
            char escape[] = { '=', hexdigit[c>>4], hexdigit[c & 0xF] };
            ret.append(escape, escape+3);
            line_length+=3;
        }
    }
    
    ret += "?=";
    return ret;
}

} // end of namespace pEpMIME::qp
} // end of namespace pEpMIME
