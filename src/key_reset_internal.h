/**
 * @internal
 * @file    key_reset_internal.h
 * @brief   Functions for resetting partner key defaults and trust and mistrusting and revoking own keys, 
 *          as well as functions to inform partners of own revoked keys and their replacements
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef KEY_RESET_INTERNAL_H
#define KEY_RESET_INTERNAL_H

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
 * @internal
 *  <!--       key_reset()       -->
 *
 *  @brief Reset the database status for a key, removing all trust information
 *         and default database connections. 
 *
 *  For own keys, also revoke the key
 *         and communicate the revocation and new key to partners we have sent
 *         mail to recently from the specific identity (i.e. address/user_id)
 *         that contacted them. We also in this case set up information so that
 *         if someone we mail uses the wrong key and wasn't yet contacted,
 *         we can send them the reset information from the right address.
 *
 *  For non-own keys, also remove key from the keyring.
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
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident
    );

PEP_STATUS key_reset_ignoring_device_group(
        PEP_SESSION session,
        const char* key_id,
        pEp_identity* ident
);

/*
PEP_STATUS key_reset_own_and_deliver_revocations(PEP_SESSION session,
                                                 identity_list** own_identities,
                                                 stringlist_t** revocations,
                                                 stringlist_t** keys);
*/

/**
 * @internal
 *  <!--       has_key_reset_been_sent()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  from_addr      const char*
 *  @param[in]  user_id        const char*
 *  @param[in]  revoked_fpr    const char*
 *  @param[in]  contacted      bool*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session,
        const char* from_addr,
        const char* user_id,
        const char* revoked_fpr,
        bool* contacted);

/**
 * @internal
 *  <!--       set_reset_contact_notified()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  own_address    const char*
 *  @param[in]  revoke_fpr     const char*
 *  @param[in]  contact_id     const char*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_UNKNOWN_DB_ERROR
 */
PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* own_address,
        const char* revoke_fpr,
        const char* contact_id
    );

/**
 * @internal
 *  <!--       receive_key_reset()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  reset_msg      message*
 *
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_MALFORMED_KEY_RESET_MSG
 *  @retval PEP_KEY_NOT_RESET
 *  @retval PEP_UNKNOWN_ERROR
 *  @retval any other value on error
 *  */
PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg);

/**
 * @internal
 *  <!--       create_standalone_key_reset_message()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  dst            message**
 *  @param[in]  own_identity   pEp_identity*
 *  @param[in]  recip          pEp_identity*
 *  @param[in]  old_fpr        const char*
 *  @param[in]  new_fpr        const char*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_UNKNOWN_ERROR
 *  @retval any other value on error
 */
PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst,
                                               pEp_identity* own_identity,
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr);


/**
 * @internal
 *  <!--       send_key_reset_to_recents()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  from_ident     pEp_identity*
 *  @param[in]  old_fpr        const char*
 *  @param[in]  new_fpr        const char*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_SYNC_NO_MESSAGE_SEND_CALLBACK
 *  @retval any other value on error
 */
PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     pEp_identity* from_ident,
                                     const char* old_fpr,
                                     const char* new_fpr);

/**
 * @internal
 *  <!--       key_reset_commands_to_PER()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session         session
 *  @param[in]  command_list    const keyreset_command_list*
 *  @param[in]  cmds            char**
 *  @param[in]  size            size_t*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS key_reset_commands_to_PER(PEP_SESSION session, const keyreset_command_list *command_list, char **cmds, size_t *size);

/**
 * @internal
 *  <!--       PER_to_key_reset_commands()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session          session
 *  @param[in]  cmds             const char*
 *  @param[in]  size             size_t
 *  @param[in]  command_list     keyreset_command_list**
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS PER_to_key_reset_commands(PEP_SESSION session, const char *cmds, size_t size, keyreset_command_list **command_list);

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
