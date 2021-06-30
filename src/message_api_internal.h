//
// Created by Krista Bennett on 14.04.21.
//

#ifndef MESSAGE_API_INTERNAL_H
#define MESSAGE_API_INTERNAL_H

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "cryptotech.h"
#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       import_attached_keys()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session         PEP_SESSION
 *  @param[in]  msg             message*
 *  @param[in]  private_idents  identity_list**
 *  @param[in]  imported_keys   stringlist_t**
 *  @param[in]  changed_keys    uint64_t*
 *
 */
bool import_attached_keys(
        PEP_SESSION session,
        message *msg,
        bool is_pEp_msg,
        identity_list **private_idents,
        stringlist_t** imported_keys,
        uint64_t* changed_keys,
        char** imported_sender_key_fpr
);

/**
 *  <!--       attach_own_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  msg         message*
 *
 */
void attach_own_key(PEP_SESSION session, message *msg);

/**
 *  <!--       determine_encryption_format()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  msg         message*
 *
 */
PEP_cryptotech determine_encryption_format(message *msg);

/**
 *  <!--       add_opt_field()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  msg         message*
 *  @param[in]  name        const char*
 *  @param[in]  value       const char*
 *
 */
void add_opt_field(message *msg, const char *name, const char *value);

/**
 *  @internal
 *
 *  <!--       try_encrypt_message()       -->
 *
 *  @brief This is the internal version of encrypt_message()
 *         to be used by asynchronous network protocol
 *         implementations. This function is calls messageToSend(NULL)
 *         in case there is a missing or wrong passphrase.
 *
 *  @param[in]  session       ession handle
 *  @param[in]  src         message*
 *  @param[in]  extra         stringlist_t*
 *  @param[in]  dst          message**
 *  @param[in]  enc_format        PEP_enc_format
 *  @param[in]  flags        PEP_encrypt_flags_t
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_SYNC_NO_CHANNEL
 *  @retval any other value on error
 *
 *  @warning    Do NOT use this function in adapters.
 *
 *  @todo KB: line up with the try_base_blahblah docs
 */
PEP_STATUS try_encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );

/**
 *  @internal
 *
 *  <!--       _rating()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    ct        PEP_comm_type
 *
 */
PEP_rating _rating(PEP_comm_type ct);

#ifdef __cplusplus
}
#endif

#endif // MESSAGE_API_INTERNAL_H
