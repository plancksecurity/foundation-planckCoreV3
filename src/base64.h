/**
 * @file    base64.h
 * @brief   Convert base64 to a binary blob - this is a convenience function
 *          used mainly to convert keys which are base64 rather than radix64
 *          (i.e. PGP armoured) encoded
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef BASE64_H
#define BASE64_H

#include "dynamic_api.h"
#include "bloblist.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       base64_str_to_binary_blob()       -->
 *
 *  @brief   Decode a base64 string and return binary format
 *
 *  converts base64 to a binary blob, putting 4 characters into
 *              3 output bytes, returning a pointer to a bloblist containing
 *              the binary blob.
 *
 *  @param[in]   input            base64 string
 *  @param[in]   length           string length
 *
 *  @retval     pointer to decoded binary blob of input string
 *  @retval     NULL on failure  
 *
 */
bloblist_t* base64_str_to_binary_blob(const char* input, int length);

#ifdef __cplusplus
}
#endif

#endif
