/**
 * @file    rating_api.h
 * @brief   rating functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef RATING_API_H
#define RATING_API_H


#include "message.h"
#include "stringpair.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 *  @enum    PEP_rating
 *
 *  @brief    TODO
 *
 */
typedef enum _PEP_rating {
    PEP_rating_undefined = 0,

    // no color

    PEP_rating_cannot_decrypt = 1,
    PEP_rating_have_no_key = 2,
    PEP_rating_unencrypted = 3,
    PEP_rating_unreliable = 5,

    PEP_rating_b0rken = -2,

    // yellow

    PEP_rating_reliable = 6,

    // green

    PEP_rating_trusted = 7,
    PEP_rating_trusted_and_anonymized = 8,
    PEP_rating_fully_anonymous = 9, 

    // red

    PEP_rating_mistrust = -1,
    PEP_rating_under_attack = -3
} PEP_rating;


/**
 *  <!--       rating_from_comm_type()       -->
 *
 *  @brief Get the rating for a comm type
 *
 *  @param[in]   ct    the comm type to deliver the rating for
 *
 *  @retval PEP_rating    rating value for comm type ct
 *
 *
 */

DYNAMIC_API PEP_rating rating_from_comm_type(PEP_comm_type ct);


/**
 *  <!--       add_rating()       -->
 *
 *  @brief add two ratings together
 *
 *  @param[in]   rating1    rating to add to
 *  @param[in]   rating2    rating added
 *
 *  @retval PEP_rating    rating value for rating1 + rating2
 *
 *
 */

DYNAMIC_API PEP_rating add_rating(PEP_rating rating1, PEP_rating rating2);


typedef PEP_STATUS (*channel_rating_t)(
        PEP_SESSION session, pEp_identity *ident, PEP_rating *rating);

/**
 *  <!--       rating_of_new_channel()       -->
 *
 *  @brief get the rating for a new channel to a communication partner
 *         outgoing messages are rated using this
 *
 *  @param[in]      session     session handle
 *  @param[in,out]  ident       identity to calculate the rating for
 *  @param[out]     rating      calculated rating
 *
 *  @retval error status or PEP_STATUS_OK on success
 *
 *  @warning this function calls update_identity() on the stored identity
*/

DYNAMIC_API PEP_STATUS rating_of_new_channel(
            PEP_SESSION session,
            pEp_identity *ident,
            PEP_rating *rating
        );


/**
 *  <!--       last_rating_of_new_channel()       -->
 *
 *  @brief get the rating of a channel to a communication partner based on last
 *         calculated comm_type
 *         this is for fast outgoing message preview ratings
 *
 *  @param[in]      session     session handle
 *  @param[in,out]  ident       identity to calculate the rating for
 *  @param[out]     rating      calculated rating
 *
 *  @retval error status or PEP_STATUS_OK on success
 *
 *  @warning this function uses a given .comm_type
 *           this function calls get_identity() if .comm_type is not given
 *           .address and .user_id must be given for a stored contact
 *           .address must be given if the identity is not from a stored contact
*/

DYNAMIC_API PEP_STATUS last_rating_of_new_channel(
            PEP_SESSION session,
            pEp_identity *ident,
            PEP_rating *rating
        );


/**
 *  <!--       rating_of_existing_channel()       -->
 *
 *  @brief get the rating for an existing channel to a communication partner
 *         incoming messages are rated using this
 *
 *  @param[in]      session     session handle
 *  @param[in]      ident       identity to calculate the rating for
 *  @param[out]     rating      calculated rating
 *
 *  @retval error status or PEP_STATUS_OK on success
 *
 *  @warning this function does not call update_identity() and expects .fpr
 *           being preset to comm_partner's key used in this channel
 *           .address and .user_id must be given for a stored contact
 *           .address must be given if the identity is not from a stored contact
*/

DYNAMIC_API PEP_STATUS rating_of_existing_channel(
            PEP_SESSION session,
            pEp_identity *ident,
            PEP_rating *rating
        );


/**
 *  <!--       outgoing_message_rating()       -->
 *
 *  @brief Get rating for an outgoing message
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to get the rating for
 *  @param[out]  rating     rating for the message
 *
 *  @retval error status or PEP_STATUS_OK on success
 *
 *  @warning msg->from must point to a valid pEp_identity
 *           msg->dir must be PEP_dir_outgoing
 *           the ownership of msg remains with the caller
 *
 */

DYNAMIC_API PEP_STATUS outgoing_message_rating(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    );


/**
 *  <!--       outgoing_message_rating_preview()       -->
 *
 *  @brief Get rating preview
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to get the rating for
 *  @param[out]  rating     rating preview for the message
 *
 *  @retval error status or PEP_STATUS_OK on success
 *
 *  @warning msg->from must point to a valid pEp_identity
 *           msg->dir must be PEP_dir_outgoing
 *           the ownership of msg remains with the caller
 *
 */

DYNAMIC_API PEP_STATUS outgoing_message_rating_preview(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    );


/** @internal
 *
 *  <!--       decrypt_rating()       -->
*/

PEP_rating decrypt_rating(PEP_STATUS status);


/**
 *  <!--       incoming_message_rating()       -->
 *
 *  @brief Get rating of an incoming message
 *
 *  @param[in]   session            session handle
 *  @param[in]   src                encrypted version of message to get the rating for
 *  @param[in]   dst                decrypted version of message to get the rating for
 *  @param[in]   known_keys         list of fprs of keys known to be used to encrypt src
 *  @param[in]   extra_keys         extra keys declared by the sender
 *  @param[in]   decrypt_status     return value of decrypt_and_verify()
 *  @param[out]  rating             rating for the message
 *
 *  @retval error status or PEP_STATUS_OK on success
 *
 *  @warning src->from must point to a valid pEp_identity
 *           src->dir must be PEP_dir_incoming
 *           src->enc_format must be set to the actual encryption format
 *           dst->_sender_fpr must be set if available
 *           dst->to[*].fpr and dst[*].fpr should be set to the keys used for
 *           recipients, respectively
 *           extra_keys are pairs (name, fpr)
 *           decrypt_status must be PEP_VERFIY_DIFFERENT_KEYS in case of a
 *           partitioned format and there is no guarantee that the sender key
 *           was being used to sign all partitions
 *
 */

DYNAMIC_API PEP_STATUS incoming_message_rating(
        PEP_SESSION session,
        const message *src,
        const message *dst,
        const stringlist_t *known_keys,
        const stringpair_list_t *extra_keys,
        PEP_STATUS decrypt_status,
        PEP_rating *rating
    );


#ifdef __cplusplus
}
#endif

#endif // RATING_API_H

