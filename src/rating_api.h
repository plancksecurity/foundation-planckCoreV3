/**
 * @file    rating_api.h
 * @brief   rating functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef RATING_API_H
#define RATING_API_H


#include "message.h"


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
 *  @warning this function calls get_identity() to retrieve the stored identity
 *           .address and .user_id must be given for a stored contact
 *           .address must be given if the identity is not from a stored contact
*/

DYNAMIC_API PEP_STATUS last_rating_of_new_channel(
            PEP_SESSION session,
            const pEp_identity *ident,
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
            const pEp_identity *ident,
            PEP_rating *rating
        );


#ifdef __cplusplus
}
#endif

#endif // RATING_API_H

