// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_BODYPARSER_HH
#define PEP_MIME_BODYPARSER_HH

#include "pEpMIME_internal.hh"
#include <deque>

namespace pEpMIME
{

    // parses the header and fill the parts in msg
    void parse_body(message* msg, const HeaderSection& headers, const std::deque<sv>& body);

}

#endif // PEP_MIME_BODYPARSER_HH
