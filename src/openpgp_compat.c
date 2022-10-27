/** 
 * @file     openpgp_compat.c 
 * @brief    Exposes functions that provide non-generic PGP-specific functionality (largely related to PGP
 *           keyrings) to adapters that need them without polluting the engine interface.
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "openpgp_compat.h"

DYNAMIC_API PEP_STATUS OpenPGP_list_keyinfo (
        PEP_SESSION session, const char* search_pattern, stringpair_list_t** keyinfo_list
    )
{
    PEP_REQUIRE(session && keyinfo_list);

    stringpair_list_t* _keyinfo_list = NULL;
    
    PEP_STATUS retval = pgp_list_keyinfo(session, search_pattern, &_keyinfo_list);
        
    if (retval == PEP_STATUS_OK)
        *keyinfo_list = _keyinfo_list;
    
    return retval;
}
