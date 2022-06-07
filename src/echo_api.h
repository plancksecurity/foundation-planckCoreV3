/**
 * @file    echo_api.h
 * @brief   echo API
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef ECHO_API_H
#define ECHO_API_H

#include "pEpEngine.h"
#include "pEp_internal.h" // for message

#include "Distribution.h" // for Distribution_t

#ifdef __cplusplus
extern "C" {
#endif


/* Public API functions
 * ***************************************************************** */

/**
 *  <!--       send_ping()       -->
 *
 *  @brief Send a ping message from the given from identity, which must be own,
 *         to the given to identity.
 *
 *  @param[in]   session      session
 *  @param[in]   from         sender identity, must be own
 *  @param[in]   to           recipient identity
 *
 *  @retval PEP_STATUS_OK            messageToSend returned with success
 *  @retval PEP_ILLEGAL_VALUE        session, from, to or messageToSend not
 *                                   defined
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval any other error status
 *          returned by messageToSend
 *
 *  @note  This automatically builds a message and sends it by calling
 *         messageToSend on it; if messageToSend fails then its return
 *         status is returned to the caller.
 *
 */
DYNAMIC_API PEP_STATUS send_ping(PEP_SESSION session,
                                 const pEp_identity *from,
                                 const pEp_identity *to);


/* Not intended for the user
 * ***************************************************************** */

/**
 *  <!--       send_pong()       -->
 *
 *  @brief Send a pong message in response to the given ping message, which
 *         must have been sent to an own identity.
 *
 *  @param[in]   ping_message     the message we are replying to: this
 *                                will always be already decrypted;
 *  @param[in]   ping_distribution_message
 *                                the Distribution_t message encoded as one of
 *                                the attechments of ping_message;
 *
 *  @retval PEP_STATUS_OK            messageToSend returned with success
 *  @retval PEP_ILLEGAL_VALUE        session, ping_message,
 *                                   ping_distribution_message or messageToSend
 *                                   not defined, ping_distribution_message
 *                                   not actually a ping message.
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval any other error status returned by messageToSend
 *
 */
PEP_STATUS send_pong(PEP_SESSION session,
                     const message *ping_message,
                     const Distribution_t *ping_distribution_message);

/**
 *  <!--       upgrade_add_echo_challange_field()       -->
 *
 *  @brief Upgrade database schema to support the Echo protocol.  Alter the
 *         identity table to add an echo_challange column, in case it is not
 *         there already.  There is no need to version this simple change.
 *
 *         This is meant to be called at engine initialisation.
 *
 *  @param[in]   session
 *
 *  @retval PEP_STATUS_OK            upgrade successful or not needed
 *  @retval PEP_UNKNOWN_DB_ERROR     unforeseen database error
 *
 */
PEP_STATUS upgrade_add_echo_challange_field(PEP_SESSION session);

/**
 *  <!--       check_pong_challenge()       -->
 *
 *  @brief Return PEP_STATUS_OK iff the given Pong message
 *         contains a response matching the stored challenge for the given
 *         identity
 *
 *  @param[in]   session          session
 *  @param[in]   identity         the identity we are dealing with
 *  @param[in]   pong_distribution_message
 *                                the Pong message
 *
 *  @retval PEP_STATUS_OK            success
 *  @retval PEP_ILLEGAL_VALUE        any argument NULL, message not a pong,
 *                                   mismatching challenge
 *  @retval PEP_UNKNOWN_DB_ERROR     unforeseen database error
 *
 */
PEP_STATUS check_pong_challenge(PEP_SESSION session,
                                const pEp_identity *identity,
                                const Distribution_t *pong_distribution_message);

/**
 *  <!--       send_ping_to_all_unknowns_in_incoming_message()       -->
 *
 *  @brief Send a Distribution.Ping message (ignoring failures) from the given
 *         incoming message's Recv-by identity to any identity for which we have
 *         no key mentioned as a non-Bcc recipeint or as a Reply-To.
 *         Notice that this should not be called blindly on any random message,
 *         as non-pEp-users would be annoyed to get pEp administrative messages.
 *         This in practice should be called when the message rating is at least
 *         PEP_rating_reliable (yellow).
 *
 *  @param[in]   session          session
 *  @param[in]   msg              the message containing potentially unknown
 *                                identities as fields
 *
 *  @retval PEP_STATUS_OK            success
 *  @retval PEP_ILLEGAL_VALUE        any argument NULL, non-incoming message,
 *                                   no Recv-by (which applications are not
 *                                               supposed to allow, but still
 *                                               happens in practice)
 *
 */
PEP_STATUS send_ping_to_all_unknowns_in_incoming_message(PEP_SESSION session,
                                                         const message *msg);

/**
 *  <!--       send_ping_to_unknown_pEp_identities_in_incoming_message()       -->
 *
 *  @brief Exactly like send_ping_to_all_unknowns_in_incoming_message , with
 *         the difference that this function only sends messages to identities
 *         known to use pEp.
 *         Rationale: an identity may be known to use pEp even if we do not
 *                    know anything about it, thanks to media keys.
 */
PEP_STATUS send_ping_to_unknown_pEp_identities_in_incoming_message(PEP_SESSION session,
                                                                   const message *msg);

/* Policy
 * ***************************************************************** */

/* The functions here help to take decisions in echo_api.c or in other
   compilation units. */

/**
 *  <!--       identity_known_to_use_pEp()       -->
 *
 *  @brief Check whether the given identity is known to use pEp, without
 *         altering it.  Even an unknown identity may be known to use pEp,
 *         thanks to media keys.
 *
 *  @param[in]   session          session
 *  @param[in]   identity         the identity being checked
 *  @param[out]  known_to_use_pEp a Boolean.  Of course false means that
 *                                we have no information, and in fact the
 *                                identity might use pEp.
 *                                Undefined on error.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL
 *  @retval PEP_OUT_OF_MEMORY     memory allocation failed
 *          possibly other failures relayed from update_identity failures
 *
 */
PEP_STATUS identity_known_to_use_pEp(PEP_SESSION session,
                                     const pEp_identity *identity,
                                     bool *known_to_use_pEp);

    
#ifdef __cplusplus
}
#endif

#endif // #ifndef ECHO_API_H
