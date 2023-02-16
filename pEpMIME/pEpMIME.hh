// This file is under GNU General Public License 3.0
// see LICENSE.txt

// This is the main header for pEp MIME, a C++ library to parse & generate MIME-compliant messages
// There exists a C wrapper that is compatible to <pEp/mime.h>


#ifndef PEP_MIME_HH
#define PEP_MIME_HH

#include "../src/message.h"

#ifdef _WIN32
#include "../src/platform_windows.h"
#endif

namespace pEpMIME
{

// multipart messages are parsed recursively up to a maximum nesting level.
// It should be large enough that all real-world mails can be parsed, but no
// stack overflow occurs on maliciously crafted messages.
// Deeper nested multipart messages are just put as attachment.
// 100 seems to be a good default value, I think.
const unsigned MaxMultipartNestingLevel = 100;


// Parse the given string loosely as an "Internet Message" that aims to be RFC 5322
// and MIME compliant (RFC 2046 etc.)
//
// parameters:
//     mime_text (in)       : an "Internet Message"
//     length (in)          : length of the mime_text, because it might contain NUL bytes
//     has_possible_pEp_msg(out): if not nullptr, the value is set to true if the attachment needs to be raised (pEp message format 2.x)
//
// return value:
//     a message struct that must be freed via free_message() or NULL on error.
//
message* parse_message(const char* mime_text, size_t length, bool* has_possible_pEp_msg = nullptr);


// Generates an RFC 5322 compliant Internet Message from the given message struct.
//
// parameters:
//    msg (in)              : the message that shall be serialized.
//    omit_fields(in)       : only encode message body and attachments
//    has_pEp_msg_attachment(in) : set forwared="no" to 1st attachment, if mime_type=="message/rfc822"
//
// return value:
//    a string holding an RFC-compliant "Internet Message", or NULL on error.
//    the string must be freed via pEp_free().
//
char* generate_message(const message* msg, bool omit_fields, bool has_pEp_msg_attachment=false);


} // end of namespace pEpMIME

#endif // PEP_MIME_HH
