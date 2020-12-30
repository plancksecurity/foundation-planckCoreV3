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


#ifdef __cplusplus
}
#endif

#endif // RATING_API_H

