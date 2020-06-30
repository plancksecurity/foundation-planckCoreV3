/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "openpgp_compat.h"

DYNAMIC_API PEP_STATUS OpenPGP_list_keyinfo (
        PEP_SESSION session, const char* search_pattern, stringpair_list_t** keyinfo_list
    )
{
    assert(session);
    assert(keyinfo_list);

    if (!(session && keyinfo_list))
        return PEP_ILLEGAL_VALUE;

    stringpair_list_t* _keyinfo_list = NULL;
    
    PEP_STATUS retval = pgp_list_keyinfo(session, search_pattern, &_keyinfo_list);
        
    if (retval == PEP_STATUS_OK)
        *keyinfo_list = _keyinfo_list;
    
    return retval;
}
