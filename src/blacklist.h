/**
 * @file    blacklist.h
 * @brief   blacklist (FIXME: derived from filename)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       blacklist_add()       -->
 *  
 *  @brief Add to blacklist
 *  
 *  @param[in]   session    session to use
 *  @param[in]   fpr        fingerprint of key to blacklist
 *  
 *  @warning there is no point in blacklisting an own key; for any own
 *           identity, this will be ignored. The correct function to use
 *           for own keys in this event is "key_reset_trust".
 *           Also, this is only effective for OpenPGP-level trust. If
 *           this key is for a pEp user, the blacklist is ignored.
 *  
 */

DYNAMIC_API PEP_STATUS blacklist_add(PEP_SESSION session, const char *fpr);


/**
 *  <!--       blacklist_delete()       -->
 *  
 *  @brief Delete from blacklist
 *  
 *  @param[in]   session    session to use
 *  @param[in]   fpr        fingerprint of key to be removed from blacklist
 *  
 *  
 */

DYNAMIC_API PEP_STATUS blacklist_delete(PEP_SESSION session, const char *fpr);


/**
 *  <!--       blacklist_is_listed()       -->
 *  
 *  @brief Is listed in blacklist
 *  
 *  @param[in]   session    session to use
 *  @param[in]   fpr        fingerprint of key to blacklist
 *  @param[out]  bool       flags if key is blacklisted
 *  
 *  
 */

DYNAMIC_API PEP_STATUS blacklist_is_listed(
        PEP_SESSION session,
        const char *fpr,
        bool *listed
    );


/**
 *  <!--       blacklist_retrieve()       -->
 *  
 *  @brief Retrieve full blacklist of key fingerprints
 *  
 *  @param[in]   session      session to use
 *  @param[out]  blacklist    copy of blacklist
 *  
 *  @ownership the ownership of the copy of blacklist goes to the caller
 *  
 */

DYNAMIC_API PEP_STATUS blacklist_retrieve(
        PEP_SESSION session,
        stringlist_t **blacklist
    );


#ifdef __cplusplus
}
#endif

