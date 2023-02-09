/**
 * @file    key_reset.h
 * @brief   Functions for resetting partner key defaults and trust and mistrusting and revoking own keys, 
 *          as well as functions to inform partners of own revoked keys and their replacements
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef KEY_RESET_H
#define KEY_RESET_H

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "message_api.h"
#include "cryptotech.h"
#include "keyreset_command.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       key_reset_identity()       -->
 *  
 *  @brief Reset the default database status for the identity / keypair
 *         provided. 
 *
 *  If this corresponds to an own identity and a private key,
 *         also revoke the key, generate a new one, and communicate the 
 *         reset to recently contacted pEp partners for this identity.
 *  
 *  If it does not, remove the key from the keyring; the key's 
 *  status is completely fresh on next contact from the partner.
 *
 *  If no key is provided, reset the identity default.
 *  Note that reset keys will be removed as defaults for all users and identities.
 *  
 *  @param[in]   session    session handle
 *  @param[in]   fpr        fingerprint of key to reset. If NULL, we reset the default key
 *                            this identity if there is one, and the user default if not.
 *  @param[in]   ident      identity for which the key reset should occur. Must contain
 *                          user_id and address. Must not be NULL.
 *                          Note: ident->fpr field will be ignored.
 *  
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
DYNAMIC_API PEP_STATUS key_reset_identity(
        PEP_SESSION session,
        pEp_identity* ident,
        const char* fpr
    );

/**
 *  <!--       key_reset_user()       -->
 *  
 *  @brief Reset the default database status for the user / keypair
 *         provided. 
 *
 *  This will effectively perform key_reset_identity()
 *         each identity associated with the key and user_id, if a key is
 *         provided, and for each key (and all of their identities) if an fpr 
 *         is not.
 *  
 *  If the user_id is the own user_id, an fpr MUST be provided.
 *  For a reset of all own user keys, call key_reset_all_own_keys() instead.
 *  Note that reset keys will be removed as defaults for all users and identities.
 *  
 *  @param[in]   session    session handle
 *  @param[in]   user_id    user_id for which the key reset should occur. If this
 *                            is the own user_id, fpr MUST NOT be NULL.
 *  @param[in]   fpr        fingerprint of key to reset.
 *                          If NULL, we reset all default
 *                          keys for this user and all of its identities.
 *                          *** However, it is forbidden to use the own user_id
 *                          here when the fpr is NULL. For this functionality,
 *                          call key_reset_all_own_keys ***
 *  
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error.  But notice that, differently from 2.x
 *          startting from pEp Engine 2.1.69, the 3.x series does not return
 *          PEP_KEY_NOT_FOUND where there is no key to reset; in that case the
 *          result will simply be PEP_STATUS_OK.
 */

//
DYNAMIC_API PEP_STATUS key_reset_user(
        PEP_SESSION session,
        const char* user_id,
        const char* fpr
    );

/**
 *  <!--       key_reset_all_own_keys()       -->
 *  
 *  @brief Revoke and mistrust all own keys, generate new keys for all 
 *         own identities, and opportunistically communicate
 *         key reset information to people we have recently 
 *         contacted. 
 *  
 *  @param[in]   session    session handle
 *  
 *  @warning HOWEVER, apps and adapters must decide if this is a reasonable state;
 *           since the period where no own user exists will necessarily be very short
 *           in most implementations, PEP_CANNOT_FIND_IDENTITY may be returned when 
 *           there is some sort of DB corruption and we expect there to be an own user.
 *           Apps are responsible for deciding whether or not this is an error condition;
 *           one would expect that it generally is (rather than the uninitialised DB case)
 *  
 */
DYNAMIC_API PEP_STATUS key_reset_all_own_keys(PEP_SESSION session);

// FIXME: Doc
// This is simply NOT SAFE for multiple passwords on the extant 
// keys. Cannot be called with multiple passwords for that purpose.
/**
 *  <!--       key_reset_own_grouped_keys()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     session handle 
 *  
 */
DYNAMIC_API PEP_STATUS key_reset_own_grouped_keys(PEP_SESSION session);


#ifdef __cplusplus
}
#endif

#endif
