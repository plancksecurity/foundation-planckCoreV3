// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif


bool import_attached_keys(
        PEP_SESSION session, 
        const message *msg,
        identity_list **private_idents
    );

void attach_own_key(PEP_SESSION session, message *msg);

PEP_cryptotech determine_encryption_format(message *msg);

void add_opt_field(message *msg, const char *name, const char *value);

typedef enum _PEP_encrypt_flags {
    // "default" means whatever the default behaviour for the function is.
    PEP_encrypt_flag_default = 0x0,
    PEP_encrypt_flag_force_encryption = 0x1,

    // This flag is for special use cases and should not be used
    // by normal pEp clients!
    PEP_encrypt_flag_force_unsigned = 0x2,
    PEP_encrypt_flag_force_no_attached_key = 0x4,
    
    // This is used for outer messages (used to wrap the real message)
    // This is only used internally and (eventually) by transport functions
    PEP_encrypt_flag_inner_message = 0x8
    
} PEP_encrypt_flags; 

typedef unsigned int PEP_encrypt_flags_t;


// encrypt_message() - encrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to encrypt
//      extra (in)          extra keys for encryption
//      dst (out)           pointer to new encrypted message or NULL if no
//                          encryption could take place
//      enc_format (in)     encrypted format
//      flags (in)          flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK                   on success
//      PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//                                      an ambiguous name
//      PEP_UNENCRYPTED                 on demand or no recipients with usable
//                                      key, is left unencrypted, and key is
//                                      attached to it
//
//  caveat:
//      the ownershop of src remains with the caller
//      the ownership of dst goes to the caller
DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );


// encrypt_message_and_add_priv_key() - encrypt message in memory, adding an encrypted private
//                                      key (encrypted separately and sent within the inner message)
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to encrypt
//      extra (in)          extra keys for encryption
//      dst (out)           pointer to new encrypted message or NULL if no
//                          encryption could take place
//      to_fpr              fingerprint of the private key that should
//                          be encrypted and attached to the message
//      enc_format (in)     encrypted format
//      flags (in)          flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK                   on success
//      PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//                                      an ambiguous name
//      PEP_UNENCRYPTED                 on demand or no recipients with usable
//                                      key, is left unencrypted, and key is
//                                      attached to it
//
//  caveat:
//      the ownershop of src remains with the caller
//      the ownership of dst goes to the caller
DYNAMIC_API PEP_STATUS encrypt_message_and_add_priv_key(
        PEP_SESSION session,
        message *src,
        message **dst,
        const char* to_fpr,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );


// encrypt_message_for_self() - encrypt message in memory for user's identity only,
//                              ignoring recipients and other identities from
//                              the message
//  parameters:
//      session (in)        session handle
//      target_id (in)      self identity this message should be encrypted for
//      src (in)            message to encrypt
//      extra (in)          extra keys for encryption
//      dst (out)           pointer to new encrypted message or NULL on failure
//      enc_format (in)     encrypted format
//      flags (in)          flags to set special encryption features
//
//  return value:       (FIXME: This may not be correct or complete)
//      PEP_STATUS_OK            on success
//      PEP_KEY_NOT_FOUND        at least one of the receipient keys
//                               could not be found
//      PEP_KEY_HAS_AMBIG_NAME   at least one of the receipient keys has
//                               an ambiguous name
//      PEP_GET_KEY_FAILED       cannot retrieve key
//
//  caveat:
//      the ownership of src remains with the caller
//      the ownership of target_id remains w/ caller            
//      the ownership of dst goes to the caller
//      message is NOT encrypted for identities other than the target_id (and then,
//      only if the target_id refers to self!)
DYNAMIC_API PEP_STATUS encrypt_message_for_self(
        PEP_SESSION session,
        pEp_identity* target_id,
        message *src,
        stringlist_t* extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );


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


typedef enum _PEP_rating {
    PEP_rating_undefined = 0,
    PEP_rating_cannot_decrypt,
    PEP_rating_have_no_key,
    PEP_rating_unencrypted,
    PEP_rating_unencrypted_for_some,
    PEP_rating_unreliable,
    PEP_rating_reliable,
    PEP_rating_trusted,
    PEP_rating_trusted_and_anonymized,
    PEP_rating_fully_anonymous,   

    PEP_rating_mistrust = -1,
    PEP_rating_b0rken = -2,
    PEP_rating_under_attack = -3
} PEP_rating;

typedef enum _PEP_color {
    PEP_color_no_color = 0,
    PEP_color_yellow,
    PEP_color_green,
    PEP_color_red = -1,
} PEP_color;


// color_from_rating - calculate color from rating
//
//  parameters:
//      rating (in)         rating
//
//  return value:           color representing that rating
DYNAMIC_API PEP_color color_from_rating(PEP_rating rating);

typedef enum _PEP_decrypt_flags {
    PEP_decrypt_flag_own_private_key = 0x1,
    PEP_decrypt_flag_consume = 0x2,
    PEP_decrypt_flag_ignore = 0x4,
    PEP_decrypt_flag_src_modified = 0x8,
    // input flags    
    PEP_decrypt_flag_untrusted_server = 0x100
} PEP_decrypt_flags; 

typedef unsigned int PEP_decrypt_flags_t;


// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (inout)         message to decrypt
//      dst (out)           pointer to new decrypted message or NULL on failure
//      keylist (out)       stringlist with keyids
//      rating (out)        rating for the message
//      flags (inout)       flags to signal special decryption features
//
//  return value:
//      error status 
//      or PEP_DECRYPTED if message decrypted but not verified
//      or PEP_CANNOT_REENCRYPT if message was decrypted (and possibly
//         verified) but a reencryption operation is expected by the caller
//         and failed
//      or PEP_STATUS_OK on success
//
//  flag values:
//      in:
//          PEP_decrypt_flag_untrusted_server
//              used to signal that decrypt function should engage in behaviour
//              specified for when the server storing the source is untrusted
//      out:
//          PEP_decrypt_flag_own_private_key
//              private key was imported for one of our addresses (NOT trusted
//              or set to be used - handshake/trust is required for that)
//          PEP_decrypt_flag_src_modified
//              indicates that the src object has been modified. At the moment,
//              this is always as a direct result of the behaviour driven
//              by the input flags. This flag is the ONLY value that should be
//              relied upon to see if such changes have taken place.
//          PEP_decrypt_flag_consume
//              used by sync 
//          PEP_decrypt_flag_ignore
//              used by sync 
//
//
// caveat:
//      the ownership of src remains with the caller - however, the contents 
//          might be modified (strings freed and allocated anew or set to NULL,
//          etc) intentionally; when this happens, PEP_decrypt_flag_src_modified
//          is set.
//      the ownership of dst goes to the caller
//      the ownership of keylist goes to the caller
//      if src is unencrypted this function returns PEP_UNENCRYPTED and sets
//         dst to NULL
DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_rating *rating,
        PEP_decrypt_flags_t *flags
);


// MIME_decrypt_message() - decrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to decrypt
//      size (in)               size of mime text to decode (in order to decrypt)
//      mime_plaintext (out)    decrypted, encoded message
//      keylist (out)           stringlist with keyids
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


// own_message_private_key_details() - details on own key in own message
//
//  parameters:
//      session (in)        session handle
//      msg (in)            message to decrypt
//      ident (out)         identity containing uid, address and fpr of key
//
//  note:
//      In order to obtain details about key to be possibly imported
//      as a replacement of key currently used as own identity, 
//      application passes message that have been previously flagged by 
//      decrypt_message() as own message containing own key to this function
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      the ownership of msg remains with the caller
//      the ownership of ident goes to the caller
//      msg MUST be encrypted so that this function can check own signature
DYNAMIC_API PEP_STATUS own_message_private_key_details(
        PEP_SESSION session,
        message *msg,
        pEp_identity **ident 
);


// outgoing_message_rating() - get rating for an outgoing message
//
//  parameters:
//      session (in)        session handle
//      msg (in)            message to get the rating for
//      rating (out)        rating for the message
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      msg->from must point to a valid pEp_identity
//      msg->dir must be PEP_dir_outgoing
//      the ownership of msg remains with the caller
DYNAMIC_API PEP_STATUS outgoing_message_rating(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    );


// identity_rating() - get rating for a single identity
//
//  parameters:
//      session (in)        session handle
//      ident (in)          identity to get the rating for
//      rating (out)        rating for the identity
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//  caveat:
//      the ownership of ident remains with the caller
DYNAMIC_API PEP_STATUS identity_rating(
        PEP_SESSION session,
        pEp_identity *ident,
        PEP_rating *rating
    );


// get_binary_path() - retrieve path of cryptotech binary if available
//
//  parameters:
//      tech (in)           cryptotech to get the binary for
//      path (out)          path to cryptotech binary or NULL if not available
//                          **path is owned by the library, do not change it!
DYNAMIC_API PEP_STATUS get_binary_path(PEP_cryptotech tech, const char **path);


// get_trustwords() - get full trustwords string for a *pair* of identities
//
//    parameters:
//        session (in)        session handle
//        id1 (in)            identity of first party in communication - fpr can't be NULL  
//        id2 (in)            identity of second party in communication - fpr can't be NULL
//        lang (in)           C string with ISO 639-1 language code
//        words (out)         pointer to C string with all trustwords UTF-8 encoded,
//                            separated by a blank each
//                            NULL if language is not supported or trustword
//                            wordlist is damaged or unavailable
//        wsize (out)         length of full trustwords string
//        full (in)           if true, generate ALL trustwords for these identities.
//                            else, generate a fixed-size subset. (TODO: fixed-minimum-entropy
//                            subset in next version)
//
//    return value:
//        PEP_STATUS_OK            trustwords retrieved
//        PEP_OUT_OF_MEMORY        out of memory
//        PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
//
//    caveat:
//        the word pointer goes to the ownership of the caller
//        the caller is responsible to free() it (on Windoze use pEp_free())
//
DYNAMIC_API PEP_STATUS get_trustwords(
    PEP_SESSION session, const pEp_identity* id1, const pEp_identity* id2,
    const char* lang, char **words, size_t *wsize, bool full
);


// get_message_trustwords() - get full trustwords string for message sender and reciever identities 
//
//    parameters:
//        session (in)        session handle
//        msg (in)            message to get sender identity from
//        keylist (in)        NULL if message to be decrypted,
//                            keylist returned by decrypt_message() otherwise
//        received_by (in)    identity for account receiving message can't be NULL
//        lang (in)           C string with ISO 639-1 language code
//        words (out)         pointer to C string with all trustwords UTF-8 encoded,
//                            separated by a blank each
//                            NULL if language is not supported or trustword
//                            wordlist is damaged or unavailable
//        full (in)           if true, generate ALL trustwords for these identities.
//                            else, generate a fixed-size subset. (TODO: fixed-minimum-entropy
//                            subset in next version)
//
//    return value:
//        PEP_STATUS_OK            trustwords retrieved
//        PEP_OUT_OF_MEMORY        out of memory
//        PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
//        error status of decrypt_message() if decryption fails.
//
//    caveat:
//        the word pointer goes to the ownership of the caller
//        the caller is responsible to free() it (on Windoze use pEp_free())
//
DYNAMIC_API PEP_STATUS get_message_trustwords(
    PEP_SESSION session, 
    message *msg,
    stringlist_t *keylist,
    pEp_identity* received_by,
    const char* lang, char **words, bool full
);

// re_evaluate_message_rating() - re-evaluate already decrypted message rating
//
//  parameters:
//      session (in)            session handle
//      msg (in)                message to get the rating for
//      x_keylist (in)          decrypted message recipients keys fpr
//      x_enc_status (in)       original rating for the decrypted message
//      rating (out)            rating for the message
//
//  return value:
//      PEP_ILLEGAL_VALUE       if decrypted message doesn't contain 
//                              X-EncStatus optional field and x_enc_status is 
//                              pEp_rating_udefined
//                              or if decrypted message doesn't contain 
//                              X-Keylist optional field and x_keylist is NULL
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      msg->from must point to a valid pEp_identity
//      the ownership of msg remains with the caller
//	    the ownership of x_keylist remains with to the caller

DYNAMIC_API PEP_STATUS re_evaluate_message_rating(
    PEP_SESSION session,
    message *msg,
    stringlist_t *x_keylist,
    PEP_rating x_enc_status,
    PEP_rating *rating
);
#ifdef __cplusplus
}
#endif
