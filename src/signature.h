/**
 * @file    signature.h
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef SIGNATURE_H
#define SIGNATURE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "platform.h"
#include "pEpEngine.h"

#define SIGNING_IDENTITY_USER_ADDRESS "signing_identity@planck.security"
#define SIGNING_IDENTITY_USER_NAME "Signing Identity"

    /**
     *  <!--       create_signing_identity()       -->
     *
     *  @brief Creates the signing identity, including a call to `myself`.
     *
     *  @param[in] session session
     *  @param[in] pEp_identity ** The identity to be filled with the created signing identity.
     *
     *  @retval PEP_STATUS_OK         success
     *
     */
    PEP_STATUS
    create_signing_identity(PEP_SESSION session, pEp_identity **signer_identity);

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
    DYNAMIC_API PEP_STATUS signature_for_text(PEP_SESSION session,
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
    DYNAMIC_API PEP_STATUS verify_signature(PEP_SESSION session,
                                            const char *ptext,
                                            size_t psize,
                                            const char *stext,
                                            size_t ssize);

#ifdef __cplusplus
}
#endif

#endif
