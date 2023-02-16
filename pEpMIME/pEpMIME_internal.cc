// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEpMIME_internal.hh"
#include <algorithm>

#include <boost/fusion/include/adapt_struct.hpp>


    template<class T>
    std::ostream& operator<<(std::ostream& o, const std::vector<T>& v)
    {
        o << '[';
        if(!v.empty())
        {
            auto q = v.begin();
            o << *q;
            ++q;
            for(; q!=v.end(); ++q)
            {
                o << ", " << *q;
            }
        }
        return o << ']';
    }
    

namespace pEpMIME
{
    using namespace std;

    void ascii_tolower_inplace(std::string& s)
    {
        for(char& c : s)
        {
            if(c>='A' && c<='Z')
            {
                c += 32;
            }
        }
    }
    
    std::string ascii_tolower(const sv& s)
    {
        std::string ret(s);
        ascii_tolower_inplace(ret);
        return ret;
    }


    // return empty string if there is no header field with that name in the HeaderSection
    sv header_value(const HeaderSection& hs, sv name)
    {
        auto q = std::find_if(hs.begin(), hs.end(), [name](const NameValue& nv) { return nv.name == name; } );
        
        return q==hs.end() ? sv{} : sv{q->value};
    }

    std::ostream& operator<<(std::ostream& o, const NameValue& p)
    {
        return o << '{' << p.name << "=“" << p.value << "”} ";
    }

    std::ostream& operator<<(std::ostream& o, const HeaderSection& hs)
    {
        return ::operator<<(o,hs);
    }

    const sv Pseudo_Header_Format = ":pEp:MIME:longmsg:format";
    const sv Pseudo_Header_Delsp  = ":pEp:MIME:longmsg:delsp";
    
    const sv Pseudo_Header_Forwarded = ":pEp:MIME:attachment1:forwarded";

} // end of namespace pEpMIME

/*
BOOST_FUSION_ADAPT_STRUCT(
    pEpMIME::NameValue,
    (std::string, name)
    (std::string, value)
)

*/
