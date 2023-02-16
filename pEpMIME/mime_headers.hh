// This file is under GNU General Public License 3.0
// see LICENSE.txt

// Defines data structures for Content-Type, Content-Disposition and Content-Transfer-Encoding headers

#ifndef PEP_MIME_MIME_HEADERS_HH
#define PEP_MIME_MIME_HEADERS_HH

#include "pEpMIME_internal.hh"

namespace pEpMIME
{
    struct ContentType
    {
        //ContentType() = default;
        explicit ContentType(sv header_line);
    
        std::string type;
        std::string subtype;
        std::vector<NameValue> tparams;
        void tolower(); // only for ASCII chars, but that's sufficient here.
        void sanitize()
        {
            tolower();
            if(type.empty()) { type = "text"; subtype="plain"; }
        }
        
        std::string mime_type() const { return type + "/" + subtype; }
    };

    struct ContentDisposition
    {
        explicit ContentDisposition(sv header_line);
        
        content_disposition_type dispo_type = PEP_CONTENT_DISP_INLINE;
        std::vector<NameValue> dparams;
    };

    struct MimeHeaders : public ContentType, public ContentDisposition
    {
        typedef char* (*Decoder)(const BodyLines&, size_t&);

        explicit MimeHeaders(const HeaderSection& headers);
        
        std::string transfer_encoding;
        Decoder decoder;
    };

    std::ostream& operator<<(std::ostream& o, const ContentType&);
    std::ostream& operator<<(std::ostream& o, const ContentDisposition&);

    std::ostream& operator<<(std::ostream& o, const MimeHeaders&);

} // end of namespace pEpMIME

#endif // PEP_MIME_MIME_HEADERS_HH
