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


/* BEGIN INTERNAL FUNCTIONS - NOT FOR EXPORT */

bool import_attached_keys(
        PEP_SESSION session, 
        const message *msg,
        identity_list **private_idents
    );
void attach_own_key(PEP_SESSION session, message *msg);

// detached sig text is returned in signature, along
// with its size in sig_size
PEP_STATUS sign_blob(PEP_SESSION session,
                     pEp_identity* signer_id,
                     bloblist_t* blob,
                     char** signature,
                     size_t* sig_size);

PEP_STATUS verify_blob(PEP_STATUS status,
                       bloblist_t* blob,
                       char* signature,
                       size_t sig_size);

// *signer_fpr is the signing key fpr, if verified
PEP_STATUS verify_beacon_message(PEP_SESSION session,
                                 message* beacon_msg,
                                 char** signer_fpr);

// beacon_msg is an in-out param - it must at least
// have beacon_msg->from filled in so we can grab the key
// with which to sign it.
PEP_STATUS prepare_beacon_message(PEP_SESSION session,
                                  char* beacon_blob,
                                  size_t beacon_size,
                                  message* beacon_msg); 

// Left in for commit, but these don't work the way we
// would intend, and the 2nd is useless because the parse
// has already removed necessary information for signed,
// not encrypted texts. If we want it, we have to
// do some significant reworking. -- KB
//
// PEP_STATUS sign_message(PEP_SESSION session,
//                       message *src,
//                       message **dst);
//             
// /* checks if a message is correctly signend
// with a key that has a UID with the email address of message.from. If
// result is PEP_VERIFIED, it additionally delivers fpr of the signature
// key. The function has to import attached keys first before doing the
// check.  It must not handle encrypted messages but give an error value
// for them. */
// PEP_STATUS check_signed_message(PEP_SESSION session,
//                                 message *src,
//                                 char** signing_key_ptr);

PEP_cryptotech determine_encryption_format(message *msg);
void add_opt_field(message *msg, const char *name, const char *value);

/* END INTERNAL FUNCTIONS - NOT FOR EXPORT */

typedef enum _PEP_encrypt_flags {
    // "default" means whatever the default behaviour for the function is.
    PEP_encrypt_flag_default = 0x0,
    PEP_encrypt_flag_force_encryption = 0x1,

    // This flag is for special use cases and should not be used
    // by normal pEp clients!
    PEP_encrypt_flag_force_unsigned = 0x2,
    PEP_encrypt_flag_force_no_attached_key = 0x4
} PEP_encrypt_flags; 

typedef unsigned int PEP_encrypt_flags_t;

// encrypt_message() - encrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to encrypt
//      extra (in)          extra keys for encryption
//      dst (out)           pointer to new encrypted message or NULL on failure
//      enc_format (in)     encrypted format
//      flags (in)          flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK                   on success
//		PEP_KEY_NOT_FOUND	            at least one of the receipient keys
//		                                could not be found
//		PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//		                                an ambiguous name
//		PEP_GET_KEY_FAILED		        cannot retrieve key
//
//	caveat:
//	    the ownershop of src remains with the caller
//	    the ownership of dst goes to the caller

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
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
//      dst (out)           pointer to new encrypted message or NULL on failure
//      enc_format (in)     encrypted format
//      flags (in)          flags to set special encryption features
//
//  return value:       (FIXME: This may not be correct or complete)
//      PEP_STATUS_OK                   on success
//		PEP_KEY_NOT_FOUND	            at least one of the receipient keys
//		                                could not be found
//		PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//		                                an ambiguous name
//		PEP_GET_KEY_FAILED		        cannot retrieve key
//
//	caveat:
//	    the ownership of src remains with the caller
//      the ownership of target_id remains w/ caller            
//	    the ownership of dst goes to the caller
//      message is NOT encrypted for identities other than the target_id (and then,
//          only if the target_id refers to self!)

DYNAMIC_API PEP_STATUS encrypt_message_for_self(
        PEP_SESSION session,
        pEp_identity* target_id,
        message *src,
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
//      target_id (in)      self identity this message should be encrypted for
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
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
    PEP_decrypt_flag_ignore = 0x4
} PEP_decrypt_flags; 

typedef unsigned int PEP_decrypt_flags_t;

// decrypt_message() - decrypt message in memory
//
//  parameters:
//      session (in)        session handle
//      src (in)            message to decrypt
//      dst (out)           pointer to new decrypted message or NULL on failure
//      keylist (out)       stringlist with keyids
//      rating (out)        rating for the message
//      flags (out)         flags to signal special decryption features
//
//  return value:
//      error status or PEP_STATUS_OK on success
//
//	caveat:
//	    the ownership of src remains with the caller
//	    the ownership of dst goes to the caller
//	    the ownership of keylist goes to the caller
//	    if src is unencrypted this function returns PEP_UNENCRYPTED and sets
//	    dst to NULL

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
//      flags (out)             flags to signal special decryption features
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
    PEP_decrypt_flags_t *flags
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
//	caveat:
//	    the ownership of msg remains with the caller
//	    the ownership of ident goes to the caller
//	    msg MUST be encrypted so that this function can check own signature

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

#ifdef __cplusplus
}
#endif
