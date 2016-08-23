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
    
//  OpenPGP_list_keyinfo() - get a key/UID list for pattern matches in keyring (NULL
//                           to return entire keyring)
//
//  parameters:
//      session (in)          session handle
//      show_revoked (in)     true if identities with revoked primary keys should also
//                            be listed; false if only valid keys should be shown
//      keyinfo_list (out)    list of identities for each available key 
//
//  caveat:
//      keyinfo_list must be freed by the caller.
DYNAMIC_API PEP_STATUS OpenPGP_list_keyinfo (
        PEP_SESSION session, const char* search_pattern, stringpair_list_t** keyinfo_list
    );
    
#ifdef __cplusplus
}
#endif

