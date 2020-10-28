/** 
 * @file     openpgp_compat.h 
 * @brief    Exposes functions that provide non-generic PGP-specific functionality (largely related to PGP
 *           keyrings) to adapters that need them without polluting the engine interface.
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
    
#include "dynamic_api.h"
#include "stringpair.h"    

#ifdef USE_SEQUOIA
#include "pgp_sequoia.h"
#endif
    
/**
 *  <!--       OpenPGP_list_keyinfo()       -->
 *  
 *  @brief Get a key/UID list for pattern matches in keyring (NULL or ""
 *         to return entire keyring), filtering out revoked keys in the results
 *  
 *  @param[in]   session           session handle
 *  @param[in]   search_pattern    search pattern - either an fpr, or something within the UID, or NULL / "" for
 *                                   all keys
 *  @param[out]  keyinfo_list      a key/value pair list for each key / UID combination
 *  
 *  @warning keyinfo_list must be freed by the caller.
 *  
 */
DYNAMIC_API PEP_STATUS OpenPGP_list_keyinfo (
        PEP_SESSION session, const char* search_pattern, stringpair_list_t** keyinfo_list
    );
    
#ifdef __cplusplus
}
#endif
