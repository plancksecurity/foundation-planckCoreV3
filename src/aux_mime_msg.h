/**
 * @file      aux_mime_msg.h
 * 
 * @brief     Auxiliary file which provides the MIME* functions for the enigmail/pEp implementation and some tests.
 *            Provides access to pEp functions for messages fed in in MIME string format instead of
 *            through the message struct.
 *
 * @deprecated These functions should no longer be used, and these files will be removed shortly.
 *
 * @warning   No version of the engine which implements pEp sync should use these functions
 *
 * @license   GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef AUX_MIME_MSG_H
#define AUX_MIME_MSG_H

#ifdef ENIGMAIL_MAY_USE_THIS

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       MIME_encrypt_message()       -->
 *
 *  @deprecated
 *
 *  @brief Encrypt a MIME message, with MIME output
 *  
 *  @param[in]   session            session handle
 *  @param[in]   mimetext           MIME encoded text to encrypt
 *  @param[in]   size               size of input mime text
 *  @param[in]   extra              extra keys for encryption
 *  @param[out]  mime_ciphertext    encrypted, encoded message
 *  @param[in]   enc_format         encrypted format
 *  @param[in]   flags              flags to set special encryption features
 *  
 *  @retval PEP_STATUS_OK                   if everything worked
 *  @retval PEP_BUFFER_TOO_SMALL            if encoded message size is too big to handle
 *  @retval PEP_CANNOT_CREATE_TEMP_FILE     if there are issues with temp files; in
 *                                          this case errno will contain the underlying
 *                                          error
 *  @retval PEP_OUT_OF_MEMORY       if not enough memory could be allocated
 *  
 *  @ownership 
 *  -  the encrypted, encoded mime text will go to the ownership of the caller 
 *  -  the original mimetext will remain in the ownership of the caller
 *
 */
DYNAMIC_API PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);


/**
 *  <!--       MIME_encrypt_message_for_self()       -->
 *
 *  @deprecated
 *
 *  @brief Encrypt MIME message for user's identity only,
 *         ignoring recipients and other identities from
 *         the message, with MIME output
 *  
 *  @param[in]   session            session handle
 *  @param[in]   target_id          self identity this message should be encrypted for
 *  @param[in]   mimetext           MIME encoded text to encrypt
 *  @param[in]   size               size of input mime text
 *  @param[in]   extra              extra keys for encryption
 *  @param[out]    mime_ciphertext    encrypted, encoded message
 *  @param[in]   enc_format         encrypted format
 *  @param[in]   flags              flags to set special encryption features
 *  
 *  @retval PEP_STATUS_OK                   if everything worked
 *  @retval PEP_BUFFER_TOO_SMALL            if encoded message size is too big to handle
 *  @retval PEP_CANNOT_CREATE_TEMP_FILE     if there are issues with temp files; in
 *                                          this case errno will contain the underlying
 *                                          error
 *  @retval PEP_OUT_OF_MEMORY       if not enough memory could be allocated
 *  
 *  @ownership 
 *  -  the encrypted, encoded mime text will go to the ownership of the caller 
 *  -  the original mimetext will remain in the ownership of the caller
 *  
 */
DYNAMIC_API PEP_STATUS MIME_encrypt_message_for_self(
    PEP_SESSION session,
    pEp_identity* target_id,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);



/**
 *  <!--       MIME_decrypt_message()       -->
 *
 *  @deprecated
 *
 *  @brief Decrypt a MIME message, with MIME output
 *  
 *  @param[in]     session           session handle
 *  @param[in]     mimetext          MIME encoded text to decrypt
 *  @param[in]     size              size of mime text to decode (in order to decrypt)
 *  @param[out]    mime_plaintext    decrypted, encoded message
 *  @param[in,out] keylist           in: stringlist with additional keyids for reencryption if needed
 *                                   (will be freed and replaced with output keylist)
 *                                   out: stringlist with keyids
 *  @param[out]    rating            rating for the message
 *  @param[in,out] flags             flags to signal special decryption features (see below)
 *  @param[out]    modified_src      modified source string, if decrypt had reason to change it
 *  
 *  @retval decrypt status                  if everything worked with MIME encode/decode, 
 *                                          the status of the decryption is returned 
 *                                          (PEP_STATUS_OK or decryption error status)
 *  @retval PEP_BUFFER_TOO_SMALL            if encoded message size is too big to handle
 *  @retval PEP_CANNOT_CREATE_TEMP_FILE     if there are issues with temp files; in
 *                                          this case errno will contain the underlying
 *                                          error
 *  @retval PEP_OUT_OF_MEMORY               if not enough memory could be allocated
 *  
 *  @note Flags above are as follows:
 *  @verbatim
 *  ---------------------------------------------------------------------------------------------|
 *  Incoming flags                                                                               |
 *  ---------------------------------------------------------------------------------------------|
 *  Flag                                  | Description                                          |                     
 *  --------------------------------------|------------------------------------------------------|
 *  PEP_decrypt_flag_untrusted_server     | used to signal that decrypt function should engage   |
 *                                        | in behaviour specified for when the server storing   |
 *                                        | the source is untrusted.                             |
 *  ---------------------------------------------------------------------------------------------|
 *  Outgoing flags                                                                               |
 *  ---------------------------------------------------------------------------------------------|
 *  PEP_decrypt_flag_own_private_key      | private key was imported for one of our addresses    |
 *                                        | (NOT trusted or set to be used - handshake/trust is  |
 *                                        | required for that)                                   |
 *                                        |                                                      |
 *  PEP_decrypt_flag_src_modified         | indicates that the modified_src field should contain | 
 *                                        | a modified version of the source, at the moment      | 
 *                                        | always as a result of the input flags.               |
 *                                        |                                                      |
 *  PEP_decrypt_flag_consume              | used by sync to indicate this was a pEp internal     |
 *                                        | message and should be consumed externally without    |
 *                                        | showing it as a normal message to the user           |
 *                                        |                                                      |
 *  PEP_decrypt_flag_ignore               | used by sync                                         |
 *  ---------------------------------------------------------------------------------------------| @endverbatim
 * 
 *  @ownership 
 *  - the decrypted, encoded mime text will go to the ownership of the caller
 *  - the original mimetext will remain in the ownership of the caller
 *  
 */
DYNAMIC_API PEP_STATUS MIME_decrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    char** mime_plaintext,
    stringlist_t **keylist,
    PEP_rating *rating,
    PEP_decrypt_flags_t *flags,
    char** modified_src
);

#ifdef __cplusplus
}
#endif

#endif

#endif
