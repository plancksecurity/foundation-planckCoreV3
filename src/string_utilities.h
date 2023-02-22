/**
 * @file    string_utilities.h
 * @brief   general-purpose string functions, not part of the Engine API
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_STRING_UTILITIES_H_
#define PEP_STRING_UTILITIES_H_

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       append_string()       -->
 *
 *  @brief Concatenate a copy of the new_part string to the end of the string
 *         pointed by big_buffer_p, reallocating big_buffer_p if necessary.
 *         This is meant to be used by first passing a pointer to NULL and 0
 *         as both used and allocated size.
 *
 *  @param[in]    session          session
 *  @param[inout] big_buffer_p     a pointer to a malloc-allocated string or a
 *                                 pointer to NULL
 *  @param[inout] big_buffer_used_size_p  pointer to the currently used size
 *                                        for the big buffer, in bytes, not
 *                                        counting the final '\0' character.
 *                                        This can be zero.
 *  @param[inout] big_buffer_allocated_size_p  pointer to the currently allocated
 *                                             size for the big buffer, in bytes,
 *                                             including '\0'.  This can be 0.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     NULL session
 *  @retval PEP_OUT_OF_MEMORY     failed to re-allocate the buffer
 *
 */
PEP_STATUS append_string(PEP_SESSION session,
                         char **big_buffer_p,
                         size_t *big_buffer_used_size_p,
                         size_t *big_buffer_allocated_size_p,
                         const char *new_part);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef PEP_STRING_UTILITIES_H_ */