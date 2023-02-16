#ifndef PEP_MIME_BODYGENERATOR_HH
#define PEP_MIME_BODYGENERATOR_HH

#include "pEpMIME_internal.hh"
#include "attachment.hh"

namespace pEpMIME
{
    // is "text/plain", optionally annotated with format=... and delsp=...
    std::string longmsg_mimetype(const message* msg);

    void generate_body(std::string& smsg, sv mime_type, sv body);
    
    // generate "multipart/alternative" body with "text/plain" and "text/html" parts
    void generate_ma_body(std::string& smsg, sv plain_mimetype, sv plain, sv html);

    // generate "multipart/mixed" body
    void generate_mm_body(std::string& smsg, sv mime_type, sv body, const std::vector<Attachment>& a);

    // complex MIME structures, depending on "det"
    // see: https://dev.pep.foundation/libpEpMIME
    void generate_complex_body(std::string& smsg, unsigned det, const message* msg, const std::vector<Attachment>& a);

} // end of namespace pEpMIME

#endif // PEP_MIME_BODYGENERATOR_HH
