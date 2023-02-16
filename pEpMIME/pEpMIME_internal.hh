// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_INTERNAL_HH
#define PEP_MIME_INTERNAL_HH

#include "pEpMIME.hh"
#include <deque>
#include <string>
#include <vector>
#include <ostream>
#include "../src/stringpair.h"

#if (__cplusplus >= 201606)  // std::string_view is C++17.
#   include <string_view>
    typedef std::string_view sv;

#else // in C++11 / C++14 use boost::string_view instead.
#   include <boost/utility/string_view.hpp>
    typedef boost::string_view sv;

    // if sv==boost::string_view these operations are not provided, neither by boost nor by the stdlib. :-(
    inline
    std::string& operator+=(std::string& s, sv v)
    {
        s.append(v.data(), v.size());
        return s;
    }

    inline
    std::string operator+(std::string s, sv v)
    {
        return s += v;
    }
    
    namespace pEpMIME { using ::operator+=; }
    
#endif // C++17 switch

#define NN(str) ( (str) ? (str) : "(NULL)" )

#ifdef LOG_TO_STDERR
#include <iostream>
#define LOG std::cerr
#else
#include "nulllogger.hh"
#define LOG nulllogger
#endif

namespace pEpMIME
{
    // works in-place
    void ascii_tolower_inplace(std::string& s);
    
    // return a copy
    std::string ascii_tolower(const sv& s);

    struct NameValue
    {
        NameValue() = default;
        NameValue(sv n, sv v)
        : name(n), value(v)
        { }
        
        std::string name, value;
    };
    
    std::ostream& operator<<(std::ostream& o, const NameValue& nv);

    // perhaps a std::list might be better?
    typedef std::vector<NameValue> HeaderSection;
    typedef std::vector<NameValue> Parameters;

    std::ostream& operator<<(std::ostream& o, const Parameters& p);

    // return empty string if there is no header field with that name in the HeaderSection
    // return first value, if there are >1 header fields with that name in the HeaderSection
    sv header_value(const HeaderSection& hs, sv name);


    typedef std::deque<sv> BodyLines;
    
    inline
    sv combineLines(const BodyLines& body)
    {
        if(body.empty())
        {
            return sv{};
        }
        const char* begin = body.front().begin();
        const char* end   = body.back().end(); 
        return sv{begin, static_cast<size_t>(end-begin)};
    }

    inline
    bool exists(const char* str)
    {
        return (str!=nullptr) && (str[0] != '\0');
    }

    // extracted from Content-Type of 1st "text/plain" MIME leaf:
    extern const sv Pseudo_Header_Format;
    extern const sv Pseudo_Header_Delsp;
    
    // extracted from Content-Type of 1st "message/rfc822" leaf:
    extern const sv Pseudo_Header_Forwarded;

} // end of namespace pEpMIME

//template<class T>
//std::ostream& operator<<(std::ostream&, const std::vector<T>& v);


#endif // PEP_MIME_INTERNAL_HH
