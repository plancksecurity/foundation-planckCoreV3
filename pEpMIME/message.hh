// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_MESSAGE_HH
#define PEP_MIME_MESSAGE_HH

#include "pEpMIME_internal.hh"
#include "mime_headers.hh"

namespace pEpMIME
{
    struct Message
    {
        explicit Message(const BodyLines& lines);
        
        HeaderSection headers;
        MimeHeaders mh;
        BodyLines body;
        
        // only set for multipart bodies
        sv boundary() const;
    };
    
    std::ostream& operator<<(std::ostream&, const Message& m);
    
} // end of namespace pEpMIME

#endif // PEP_MIME_MESSAGE_HH
