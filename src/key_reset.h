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
 *         provided. If this corresponds to an own identity and a private key,
 *         also revoke the key, generate a new one, and communicate the 
 *         reset to recently contacted pEp partners for this identity.
 *  
 *  If it does not, remove the key from the keyring; the key's 
 *  status is completely fresh on next contact from the partner.
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
 *         provided. This will effectively perform key_reset_identity()
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
 *  @param[in]  session     PEP_SESSION
 *  
 */
DYNAMIC_API PEP_STATUS key_reset_own_grouped_keys(PEP_SESSION session);

/**
 *  <!--       key_reset()       -->
 *  
 *  @brief Reset the database status for a key, removing all trust information
 *         and default database connections. For own keys, also revoke the key
 *         and communicate the revocation and new key to partners we have sent
 *         mail to recently from the specific identity (i.e. address/user_id)
 *         that contacted them. We also in this case set up information so that
 *         if someone we mail uses the wrong key and wasn't yet contacted,
 *         we can send them the reset information from the right address. 
 *         For non-own keys, also remove key from the keyring.
 *  
 *  Can be called manually or through another protocol.
 *  
 *  @param[in]   session    session handle
 *  @param[in]   fpr        fingerprint of key to reset. If NULL and ident is NULL,
 *                            we reset all keys for the own user. If NULL and ident is
 *                            an own identity, we reset the default key for that
 *                            identity. If that own identity has no default key, we
 *                            reset the user default.
 *                            if it is NULL and there is a non-own identity, we will reset
 *                            the default key for this identity if present, and user if not.
 *  @param[in]   ident      identity for which the key reset should occur.
 *                            if NULL and fpr is non-NULL, we'll reset the key for all
 *                            associated identities. If both ident and fpr are NULL, see
 *                            the fpr arg documentation.
 *                            ***IF there is an ident, it must have a user_id.***
 *                            Note: ident->fpr is always ignored
 *                            Caveat: this is now used in large part for internal calls.
 *                            external apps should call key_reset_identity and key_reset_userdata
 *                            and this function should probably be removed from the dynamic api
 *  
 *  
 */
PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident
    );

/*
PEP_STATUS key_reset_own_and_deliver_revocations(PEP_SESSION session, 
                                                 identity_list** own_identities, 
                                                 stringlist_t** revocations, 
                                                 stringlist_t** keys);
*/

/**
 *  <!--       has_key_reset_been_sent()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  from_addr      const char*
 *  @param[in]  user_id        const char*
 *  @param[in]  revoked_fpr    const char*
 *  @param[in]  contacted      bool*
 *  
 */
PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* from_addr,
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted);

/**
 *  <!--       set_reset_contact_notified()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  own_address    const char*
 *  @param[in]  revoke_fpr     const char*
 *  @param[in]  contact_id     const char*
 *  
 */
PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* own_address,
        const char* revoke_fpr,
        const char* contact_id
    );

/**
 *  <!--       receive_key_reset()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  reset_msg      message*
 *  
 */
PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg);

/**
 *  <!--       create_standalone_key_reset_message()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  dst            message**
 *  @param[in]  own_identity   pEp_identity*
 *  @param[in]  recip          pEp_identity*
 *  @param[in]  old_fpr        const char*
 *  @param[in]  new_fpr        const char*
 *  
 */
PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* own_identity,
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr);

                                               
/**
 *  <!--       send_key_reset_to_recents()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  from_ident     pEp_identity*
 *  @param[in]  old_fpr        const char*
 *  @param[in]  new_fpr        const char*
 *  
 */
PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     pEp_identity* from_ident,
                                     const char* old_fpr, 
                                     const char* new_fpr);
 
/**
 *  <!--       key_reset_commands_to_PER()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  command_list    const keyreset_command_list*
 *  @param[in]  cmds            char**
 *  @param[in]  size            size_t*
 *  
 */
PEP_STATUS key_reset_commands_to_PER(const keyreset_command_list *command_list, char **cmds, size_t *size);
/**
 *  <!--       PER_to_key_reset_commands()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  cmds             const char*
 *  @param[in]  size             size_t
 *  @param[in]  command_list     keyreset_command_list**
 *  
 */
PEP_STATUS PER_to_key_reset_commands(const char *cmds, size_t size, keyreset_command_list **command_list);

PEP_STATUS key_reset_managed_group(PEP_SESSION session,
                                   pEp_identity* group_identity,
                                   pEp_identity* manager);

PEP_STATUS generate_own_commandlist_msg(PEP_SESSION session,
                                        identity_list* reset_idents,
                                        bool ignore_ungrouped,
                                        pEp_identity* alt_sender,
                                        pEp_identity* alt_recip,
                                        const char* old_fpr,
                                        message** dst);

#ifdef __cplusplus
}
#endif

#endif
