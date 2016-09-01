// openpgp_compat.h
//
// These functions are the exposure of non-generic PGP-specific functionality (largely related to PGP
// keyrings) to adapters that need them without polluting the engine interface.
//
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
    
#include "dynamic_api.h"
#include "stringpair.h"    

#ifdef USE_GPG
#include "pgp_gpg.h"
#else
#ifdef USE_NETPGP
#include "pgp_netpgp.h"
#endif
#endif    
    
//  OpenPGP_list_keyinfo() - get a key/UID list for pattern matches in keyring (NULL or ""
//                           to return entire keyring), filtering out revoked keys in the results
//
//  parameters:
//      session (in)          session handle
//      search_pattern (in)   search pattern - either an fpr, or something within the UID, or NULL / "" for
//                            all keys
//      keyinfo_list (out)    a key/value pair list for each key / UID combination
//
//  caveat:
//      keyinfo_list must be freed by the caller.
DYNAMIC_API PEP_STATUS OpenPGP_list_keyinfo (
        PEP_SESSION session, const char* search_pattern, stringpair_list_t** keyinfo_list
    );
    
#ifdef __cplusplus
}
#endif

