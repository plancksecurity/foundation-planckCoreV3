// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_HEADERPARSER_HH
#define PEP_MIME_HEADERPARSER_HH

#include "pEpMIME_internal.hh"
#include <map>

namespace pEpMIME
{

    struct HeaderBase
    {
        HeaderBase(sv _name) : m_name(_name) {}
        virtual ~HeaderBase() = default;
        virtual void assign(message* msg, sv) = 0;
        virtual void output(std::string& out, const message* msg) = 0;
        
        sv name() const { return m_name; }
        
    protected:
        sv m_name;
    };

    typedef std::map<std::string, HeaderBase*> HeadersMap;

    const HeadersMap& headersMap();

    void add_opt_field(message* msg, const sv& name, sv value);

    // parses the header and fill the parts in msg
    void parse_header(message* msg, const HeaderSection& headers);

}

#endif
