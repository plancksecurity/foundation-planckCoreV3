/**
 * @file    signature.h
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     *  <!--       signature_for_text()       -->
     *
     *  @brief Calculates a signature for a given input text.
     *
     *  @note A special own identity is used, and at the moment no special handling
     *   is taking place when it gets renewed between a call to generating a signature
     *   and trying to verify it.
     *
     *  @param[in] session session
     *  @param[in] ptext The text to sign
     *  @param[in] psize The size of the text to sign, in bytes, excluding any terminating \0
     *  @param[out] stext The signature text
     *  @param[out] ssize The size of the signature text, in bytes, excluding any terminating \0
     *
     *  @retval PEP_STATUS_OK         success
     *
     */
    PEP_STATUS signature_for_text(PEP_SESSION session,
                                  const char *ptext,
                                  size_t psize,
                                  char **stext,
                                  size_t *ssize);

    /**
     *  <!--       verify_signature()       -->
     *
     *  @brief Verifies that a given text corresponds to a given signature.
     *
     *  @param[in] session session
     *  @param[in] ptext The text to verify
     *  @param[in] psize The size of the text to verify, in bytes, excluding any terminating \0
     *  @param[out] stext The signature text
     *  @param[out] ssize The size of the signature text, in bytes, excluding any terminating \0
     *
     *  @retval PEP_VERIFIED The given text has been signed with the given signature.
     *
     */
    PEP_STATUS verify_signature(PEP_SESSION session,
                                const char *ptext,
                                size_t psize,
                                const char *stext,
                                size_t ssize);

#ifdef __cplusplus
}
#endif

#endif
