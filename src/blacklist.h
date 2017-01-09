// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

// blacklist_add() - add to blacklist
//
//  parameters:
//      session (in)        session to use
//      fpr (in)            fingerprint of key to blacklist

DYNAMIC_API PEP_STATUS blacklist_add(PEP_SESSION session, const char *fpr);


// blacklist_delete() - delete from blacklist
//
//  parameters:
//      session (in)        session to use
//      fpr (in)            fingerprint of key to blacklist

DYNAMIC_API PEP_STATUS blacklist_delete(PEP_SESSION session, const char *fpr);


// blacklist_is_listed() - is_listed from blacklist
//
//  parameters:
//      session (in)        session to use
//      fpr (in)            fingerprint of key to blacklist
//      bool (out)          flags if key is blacklisted

DYNAMIC_API PEP_STATUS blacklist_is_listed(
        PEP_SESSION session,
        const char *fpr,
        bool *listed
    );


// blacklist_retrieve() - retrieve full blacklist of key fingerprints
//
//  parameters:
//      session (in)        session to use
//      blacklist (out)     copy of blacklist
//
//  caveat:
//      the ownership of the copy of blacklist goes to the caller

DYNAMIC_API PEP_STATUS blacklist_retrieve(
        PEP_SESSION session,
        stringlist_t **blacklist
    );


#ifdef __cplusplus
}
#endif

