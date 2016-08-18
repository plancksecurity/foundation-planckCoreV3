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
//  caveat: FIXME
//        the ownership of the identity list goes to the caller
//        the caller must use free_identity_list() to free it
//        identity objects derived from the keyring only have the available information
//           from the keyring; some fields may be NULL
DYNAMIC_API PEP_STATUS OpenPGP_list_keyinfo (
        PEP_SESSION session, stringpair_list_t** keyinfo_list, char* search_pattern
    );
    
#ifdef __cplusplus
}
#endif