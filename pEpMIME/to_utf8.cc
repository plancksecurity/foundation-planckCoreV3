// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "to_utf8.hh"
#include "string_case.hh"
#include "nfc.hh"  // for toUtf8() of single codepoints. :-)
#include <algorithm>
#include <boost/algorithm/string/case_conv.hpp>
#include <iconv.h>
#include <memory>

namespace
{
    ///////// Dirrrrrty iconv hack:
    template<class Dummy> struct SecondParam final {};
    template<class Ret, class Param1st, class Param2nd, class P3, class P4, class P5>
    struct SecondParam<Ret(*)(Param1st, Param2nd*, P3, P4, P5)>
    {
        typedef Param2nd Type;
    };

    // might be 'char*' or 'const char*' depending on iconv() implementation
    typedef SecondParam<decltype(&iconv)>::Type InBufType;
    ///////// End of iconv hack.


    struct Enc { uint32_t from,to; };
    
    static
    std::string hex(uint8_t u)
    {
        char buf[8];
        snprintf(buf,7,"0x%02hhx", u);
        return buf;
    }
    
//    constexpr
//    bool operator<(const Enc a, const Enc b) { return a.from < b.from; }

    constexpr
    bool operator<(const Enc a, uint32_t u) { return a.from < u; }
    
    struct FlatMap
    {
        constexpr
        FlatMap(const Enc* _begin, const Enc* _end)
        : min_element{_begin[0].from}
        , b{_begin}, e{_end}
        {}
        
        uint32_t operator[](uint32_t x) const
        {
            if(x<min_element)
                return x;
            
            const Enc* f = std::lower_bound(b, e, x);
            return (f == e || f->from != x) ? x : f->to;
        }
        
        const uint32_t min_element;
        const Enc* b;
        const Enc* e;
    };
    
    // Windows Latin 1 aka CP 1252 wich shall be used even for "ISO 8859-1" due to buggy encoders.
    const Enc cp_1252[] = {
        {0x80, 0x20AC}, {0x82, 0x201a}, {0x83, 0x0192}, {0x84, 0x201e}, {0x85, 0x2026}, {0x86, 0x2020}, {0x87, 0x2021},
        {0x88, 0x02c6}, {0x89, 0x2030}, {0x8a, 0x0160}, {0x8b, 0x2039}, {0x8c, 0x0152}, {0x8e, 0x017d},
        {0x91, 0x2018}, {0x92, 0x2019}, {0x93, 0x201c}, {0x94, 0x201d}, {0x95, 0x2022}, {0x96, 0x2013}, {0x97, 0x2014},
        {0x98, 0x02dc}, {0x99, 0x2122}, {0x9a, 0x0161}, {0x9b, 0x203a}, {0x9c, 0x0153}, {0x9e, 0x017e}, {0x9f, 0x0178}
    };
    const size_t cp_1252_size = sizeof(cp_1252)/sizeof(cp_1252[0]);
    
    const FlatMap CP_1252(cp_1252, cp_1252 + cp_1252_size);

    std::string from_latin1(sv s)
    {
        std::string ret;
        for(char c:s)
        {
            const char32_t c32 = CP_1252[ (unsigned char)c ];
            toUtf8(c32, ret);
        }
        return ret;
    }


static const size_t IconvBufSize = 64;

std::string to_utf8_iconv(const sv& charset, sv s)
{
    iconv_t ict = iconv_open("UTF-8", charset.data());
    if(ict == (iconv_t)-1)
    {
        if(errno==EINVAL)
        {
            throw std::runtime_error("Cannot convert from charset \"" + std::string(charset) + "\" to UTF-8.");
        }else{
            throw std::runtime_error(std::string("Internal error: ") + strerror(errno) );
        }
    }
    
    // be exception-safe from here on:
    auto ict_wrapper = std::unique_ptr<void, decltype(&iconv_close)>( ict, &iconv_close);
    
    std::string ret;
    ret.reserve(s.size());
    
    char buffer[ IconvBufSize ];
    InBufType in_p = const_cast<InBufType>(s.data());  // iconv sucks.
    size_t in_len = s.size();
    
    LOG << "to_utf8_iconv(): in_len=" << in_len << ". BufSize=" << IconvBufSize << "\n";
    
    while(in_len)
    {
        char* out_p = buffer;
        size_t out_len = IconvBufSize;
        errno = 0;
        const size_t r = iconv(ict, &in_p, &in_len, &out_p, &out_len);

        LOG << "\ticonv() returns " << r << ". out_len=" << out_len << ", in_len=" << in_len << ". out_p-buffer=" << (out_p-buffer) << ".\n";

        if(r==static_cast<size_t>(-1))
        {
#ifdef WIN32
            if(errno == E2BIG || errno == 0) // iconv() on Windows does not set errno properly. -.-
#else
            if(errno == E2BIG)
#endif
            {
                // ignore
                LOG << "\terrno==E2BIG.\n";
            }else{
                // skip octet
                LOG << "\tSKIP OKTET " << hex(*in_p) << ". errno==" << errno << ".\n";
                ++in_p;
                --in_len;
            }
        }
        ret.append(buffer, buffer + IconvBufSize - out_len);
    }
    
    return ret;
}


} // end of anonymous namespace


std::string to_utf8( const sv& charset, sv s)
{
    std::string charset_upper{charset};
    boost::algorithm::to_upper(charset_upper);

    switch( lcase_hash(charset_upper) )
    {
        case "UTF-8"_lcase :
        case "UTF8"_lcase  : return std::string{s};
        case "CP1252"_lcase:
        case "CP_1252"_lcase:
        case "ISO-8859-1"_lcase: return from_latin1(s);
    }
    // all other charsets: let's do that by libiconv. :-/
    return to_utf8_iconv(charset, s);
}

