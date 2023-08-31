/**
 * @file    log_sign.h
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef LOG_SIGN_H
#define LOG_SIGN_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     *  <!--       log_sign()       -->
     *
     *  @brief Calculates a signature for a given input text.
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
    PEP_STATUS log_sign(PEP_SESSION session,
                        const char* ptext,
                        size_t psize,
                        char** stext,
                        size_t* ssize);

    /**
     *  <!--       log_verify()       -->
     *
     *  @brief Verifies that a given text corresponds to a given signature.
     *
     *  @param[in] session session
     *  @param[in] ptext The text to verify
     *  @param[in] psize The size of the text to verify, in bytes, excluding any terminating \0
     *  @param[out] stext The signature text
     *  @param[out] ssize The size of the signature text, in bytes, excluding any terminating \0
     *
     *  @retval PEP_STATUS_OK success
     *  @retval PEP_VERIFIED success
     *  @retval PEP_VERIFY_SIGNER_KEY_REVOKED success
     *
     */
    PEP_STATUS log_verify(PEP_SESSION session,
                          const char* ptext,
                          size_t psize,
                          const char* stext,
                          size_t ssize);

#ifdef __cplusplus
}
#endif

#endif
