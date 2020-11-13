/**
 * @file    blacklist.h
 * @brief   Functions for maintaining a key blacklist for OpenPGP keys
 *          (i.e. keys received from OpenPGP partners). This is currently
 *          used by users when an OpenPGP partner has indicated that they
 *          do not want us to use a particular key we may have for them.
 *          This is marked as deprecated because we want users to use
 *          key reset instead, and this code will be in fact removed
 *          in Release 2.2.0 when key election is also removed.
 *
 * @deprecated These files are still in use as of Release 2.1 and will be removed with key election removal.
 *
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
 *  @deprecated As of Release 2.2.0
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
 *  @deprecated As of Release 2.2.0
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
 *  @deprecated As of Release 2.2.0
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
 *  @deprecated As of Release 2.2.0
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

