/**
 * @file    echo_api.h
 * @brief   echo API
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef ECHO_API_H
#define ECHO_API_H

/* FIXME: add a distribution_api.h #include'ing all the protocols of this family. */

#include "pEpEngine.h"
#include "pEp_internal.h" // for message

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 *  <!--       send_pong()       -->
 *  
 *  @param[in]   ping_message     the message we are replying to: this
 *                                will always be already decrypted and
 *                                decoded.
 *                                This function destroys the ping message
 *                                when it succeeds.

 FIXME: I think the next paragraph is now wrong: the argument used to hav e type
 message *

 *                                This is either the unencrypted transported
 *                                message or the inner message: in either case
 *                                it is what _decrypt_message returns.
 *
 *  @retval PEP_STATUS_OK            messageToSend returned with success
 *  @retval PEP_ILLEGAL_VALUE        session, ping_message or messageToSend
 *                                   not defined; ping_message not actually
 *                                   a ping message
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval any other error status returned by messageToSend
 *
 *  @brief 
 *  
 */
PEP_STATUS send_pong(PEP_SESSION session,
                     message *ping_message);

#ifdef __cplusplus
}
#endif

#endif // #ifndef ECHO_API_H
