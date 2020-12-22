// This file is under GNU General Public License 3.0
// see LICENSE.txt

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

// MIME_encrypt_message() - encrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
//      extra (in)              extra keys for encryption
//      mime_ciphertext (out)   encrypted, encoded message
//      enc_format (in)         encrypted format
//      flags (in)              flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the encrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
DYNAMIC_API PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);


// MIME_encrypt_message_for_self() - encrypt MIME message for user's identity only,
//                              ignoring recipients and other identities from
//                              the message, with MIME output
//  parameters:
//      session (in)            session handle
//      target_id (in)          self identity this message should be encrypted for
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
//      extra (in)              extra keys for encryption
//      mime_ciphertext (out)   encrypted, encoded message
//      enc_format (in)         encrypted format
//      flags (in)              flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the encrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
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



// MIME_decrypt_message() - decrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to decrypt
//      size (in)               size of mime text to decode (in order to decrypt)
//      mime_plaintext (out)    decrypted, encoded message
//      keylist (inout)         in: stringlist with additional keyids for reencryption if needed
//                                  (will be freed and replaced with output keylist)
//                              out: stringlist with keyids
//      rating (out)            rating for the message
//      flags (inout)           flags to signal special decryption features (see below)
//      modified_src (out)      modified source string, if decrypt had reason to change it
//
//  return value:
//      decrypt status          if everything worked with MIME encode/decode, 
//                              the status of the decryption is returned 
//                              (PEP_STATUS_OK or decryption error status)
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  flag values:
//      in:
//          PEP_decrypt_flag_untrusted_server
//              used to signal that decrypt function should engage in behaviour
//              specified for when the server storing the source is untrusted.
//      out:
//          PEP_decrypt_flag_own_private_key
//              private key was imported for one of our addresses (NOT trusted
//              or set to be used - handshake/trust is required for that)
//          PEP_decrypt_flag_src_modified
//              indicates that the modified_src field should contain a modified
//              version of the source, at the moment always as a result of the
//              input flags. 
//          PEP_decrypt_flag_consume
//              used by sync 
//          PEP_decrypt_flag_ignore
//              used by sync 
// 
//  caveat:
//      the decrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
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
