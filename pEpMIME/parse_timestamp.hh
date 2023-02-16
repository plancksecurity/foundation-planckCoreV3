// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_PARSE_TIMESTAMP_HH
#define PEP_MIME_PARSE_TIMESTAMP_HH

#include "pEpMIME_internal.hh" // for string_view typedef sv
#include "../src/pEpEngine.h"
#include <string>

namespace pEpMIME
{

    // parses a string like "Mon, 12 Nov 2018 13:05:46 +0100"
    timestamp* parse_timestamp(sv s);

}

#endif // PEP_MIME_PARSE_TIMESTAMP_HH
