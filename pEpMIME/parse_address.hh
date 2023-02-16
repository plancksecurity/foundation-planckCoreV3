// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_MIME_PARSE_ADDRESS_HH
#define PEP_MIME_PARSE_ADDRESS_HH

#include "pEpMIME_internal.hh" // for string_view typedef sv
#include "../src/pEpEngine.h"
#include "../src/identity_list.h"
#include <string>

namespace pEpMIME
{

    // parses a string like "Alice <alice@pep.example>"
    pEp_identity* parse_address(sv s);

    // parses a comma-separated list of e-mail addresses
    identity_list* parse_address_list(sv s);
}

#endif // PEP_MIME_PARSE_IDENTITY_HH
