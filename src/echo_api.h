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


/* Initialisation and finalisation.
 * ***************************************************************** */

/* The functions here are called when a session is initialised or finalised. */

/**
 *  <!--       echo_initialize()       -->
 *
 *  @brief Initialize session-wide support for the Echo protocol.
 *         This is called at initialisation, *after* the DB subsystem
 *         has alraedy been initialised.
 *
 *  @param[in]   session          session
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     NULL session or db within session
 *  @retval PEP_UNKNOWN_DB_ERROR  database error
 *
 */
PEP_STATUS echo_initialize(PEP_SESSION session);

/**
 *  <!--       echo_finalise()       -->
 *
 *  @brief Finalise session-wide support for the Echo protocol.
 *
 *  @param[in]   session          session
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     NULL session
 *
 */
PEP_STATUS echo_finalize(PEP_SESSION session);


/* Sending Ping and Pong messages.
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
 *  @retval PEP_STATUS_OK            messageToSend returned with success, or
 *                                   Ping not send because of rate limitation
 *                                   (not considered an error)
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
PEP_STATUS send_ping(PEP_SESSION session,
                     const pEp_identity *from,
                     const pEp_identity *to);


/**
 *  <!--       send_pong()       -->
 *
 *  @brief Send a Pong message in response to the given Ping message, which
 *         must have been sent to an own identity.
 *
 *  @param[in]   ping_message     the message we are replying to: this
 *                                will always be already decrypted;
 *  @param[in]   ping_distribution_message
 *                                the Distribution_t message encoded as one of
 *                                the attechments of ping_message;
 *
 *  @retval PEP_STATUS_OK            messageToSend returned with success, or
 *                                   Pong not send because of rate limitation
 *                                   (not considered an error)
 *  @retval PEP_ILLEGAL_VALUE        session, ping_message,
 *                                   ping_distribution_message or messageToSend
 *                                   not defined, ping_distribution_message
 *                                   not actually a Ping message.
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval any other error status returned by messageToSend
 *
 */
PEP_STATUS send_pong(PEP_SESSION session,
                     const message *ping_message,
                     const Distribution_t *ping_distribution_message);

/**
 *  <!--       handle_pong()       -->
 *
 *  @brief Handle a received Pong message; check the challenge and, in case
 *         of success, send a SYNC_NOTIFY_OUTGOING_RATING_CHANGE notification.
 *
 *  @param[in]   session          session
 *  @param[in]   own_identity     the identity which received the Pong message
 *  @param[in]   partner_identity the communication partner we are dealing with
 *  @param[in]   pong_distribution_message
 *                                the Pong message
 *
 *  @retval PEP_STATUS_OK            success: response matches stored challenge,
 *                                   notification sent.
 *  @retval PEP_DISTRIBUTION_ILLEGAL_MESSAGE
 *                                   mismatching reponse
 *  @retval PEP_SYNC_NO_NOTIFY_CALLBACK
 *                                   no notifyCallback, but correct reponse
 *  @retval PEP_ILLEGAL_VALUE        any argument NULL, message not a Pong
 *  @retval PEP_OUT_OF_MEMORY        cannot allocate memory
 *  @retval PEP_UNKNOWN_DB_ERROR     unforeseen database error
 *  @retval                          any other error code relayed from
 *                                   notifyChallenge
 *
 */
PEP_STATUS handle_pong(PEP_SESSION session,
                       const pEp_identity *own_identity,
                       const pEp_identity *partner_identity,
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

/**
 *  <!--       send_ping_to_unknown_pEp_identities_in_outgoing_message()       -->
 *
 *  @brief Like send_ping_to_unknown_pEp_identities_in_incoming_message ,
 *         for outgoing messages.
 *         Rationale: an identity may be known to use pEp even if we do not
 *                    know anything about it, thanks to media keys.
 *                    This is useful when composing a message: we might be
 *                    able to receive a Pong, and therefore a recipient key,
 *                    even before sending; this is a way to improve the
 *                    outgoing message rating.
 */
PEP_STATUS send_ping_to_unknown_pEp_identities_in_outgoing_message(PEP_SESSION session,
                                                                   const message *msg);


/* Tuning parameters.
 * ***************************************************************** */

/* This macro defines the minimum number of elapsed seconds between Echo
   messages sent by us (any session, same device) to the same identity.

   We do not distinguish between Ping and Pong messages, since we want to
   rate-limit both:
   - We rate-limit Ping messages in order not to send a flood of messages when
     we are waiting for a response;
   - We rate-limit Pong messages in order to avoid DoS attacks in which the
     message rate is amplified, which can happen in mailing lists.

   Of course period = 1 / frequency, and saying "minimum period" is like
   saying "maximum frequency". */
#define PEP_MINIMUM_ECHO_MESSAGES_PERIOD_IN_SECONDS  \
    (60 * 30) /* 30 minutes */

#ifdef __cplusplus
}
#endif

#endif // #ifndef ECHO_API_H
