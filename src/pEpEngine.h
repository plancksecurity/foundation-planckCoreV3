// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_ENGINE_H
#define PEP_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "dynamic_api.h"
#include "stringlist.h"
#include "stringpair.h"
#include "labeled_int_list.h"    
#include "timestamp.h"

#define PEP_VERSION "2.1" // pEp *protocol* version

// RELEASE version this targets
// (string: major.minor.patch)
#define PEP_ENGINE_VERSION "2.1.50"
#define PEP_ENGINE_VERSION_MAJOR 2
#define PEP_ENGINE_VERSION_MINOR 1
#define PEP_ENGINE_VERSION_PATCH 50
#define PEP_ENGINE_VERSION_RC    0


#define PEP_OWN_USERID "pEp_own_userId"
    
// pEp Engine API

//  caveat:
//      Unicode data has to be normalized to NFC before calling
//      UTF-8 strings are UTF-8 encoded C strings (zero terminated)


struct _pEpSession;
typedef struct _pEpSession * PEP_SESSION;

typedef enum {
    PEP_STATUS_OK                                   = 0,

    PEP_INIT_CANNOT_LOAD_CRYPTO_LIB                 = 0x0110,
    PEP_INIT_CRYPTO_LIB_INIT_FAILED                 = 0x0111,
    PEP_INIT_NO_CRYPTO_HOME                         = 0x0112,
//    PEP_INIT_NETPGP_INIT_FAILED                     = 0x0113,
    PEP_INIT_CANNOT_DETERMINE_CRYPTO_VERSION        = 0x0114,
    PEP_INIT_UNSUPPORTED_CRYPTO_VERSION             = 0x0115,
    PEP_INIT_CANNOT_CONFIG_CRYPTO_AGENT             = 0x0116,

    PEP_INIT_SQLITE3_WITHOUT_MUTEX                  = 0x0120,
    PEP_INIT_CANNOT_OPEN_DB                         = 0x0121,
    PEP_INIT_CANNOT_OPEN_SYSTEM_DB                  = 0x0122,
    PEP_INIT_DB_DOWNGRADE_VIOLATION                 = 0x0123,                        
    PEP_UNKNOWN_DB_ERROR                            = 0x01ff,
    
    PEP_KEY_NOT_FOUND                               = 0x0201,
    PEP_KEY_HAS_AMBIG_NAME                          = 0x0202,
    PEP_GET_KEY_FAILED                              = 0x0203,
    PEP_CANNOT_EXPORT_KEY                           = 0x0204,
    PEP_CANNOT_EDIT_KEY                             = 0x0205,
    PEP_KEY_UNSUITABLE                              = 0x0206,
    PEP_MALFORMED_KEY_RESET_MSG                     = 0x0210,
    PEP_KEY_NOT_RESET                               = 0x0211,
    PEP_CANNOT_DELETE_KEY                           = 0x0212,

    PEP_KEY_IMPORTED                                = 0x0220,
    PEP_NO_KEY_IMPORTED                             = 0x0221,
    PEP_KEY_IMPORT_STATUS_UNKNOWN                   = 0x0222,
    PEP_SOME_KEYS_IMPORTED                          = 0x0223,
    
    PEP_CANNOT_FIND_IDENTITY                        = 0x0301,
    PEP_CANNOT_SET_PERSON                           = 0x0381,
    PEP_CANNOT_SET_PGP_KEYPAIR                      = 0x0382,
    PEP_CANNOT_SET_IDENTITY                         = 0x0383,
    PEP_CANNOT_SET_TRUST                            = 0x0384,
    PEP_KEY_BLACKLISTED                             = 0x0385,
    PEP_CANNOT_FIND_PERSON                          = 0x0386,
    PEP_CANNOT_SET_PEP_VERSION                      = 0X0387,
    
    PEP_CANNOT_FIND_ALIAS                           = 0x0391,
    PEP_CANNOT_SET_ALIAS                            = 0x0392,
    
    PEP_UNENCRYPTED                                 = 0x0400,
    PEP_VERIFIED                                    = 0x0401,
    PEP_DECRYPTED                                   = 0x0402,
    PEP_DECRYPTED_AND_VERIFIED                      = 0x0403,
    PEP_DECRYPT_WRONG_FORMAT                        = 0x0404,
    PEP_DECRYPT_NO_KEY                              = 0x0405,
    PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH            = 0x0406,
    PEP_VERIFY_NO_KEY                               = 0x0407,
    PEP_VERIFIED_AND_TRUSTED                        = 0x0408,
    PEP_CANNOT_REENCRYPT                            = 0x0409,
    PEP_VERIFY_SIGNER_KEY_REVOKED                   = 0x040a,
    PEP_CANNOT_DECRYPT_UNKNOWN                      = 0x04ff,


    PEP_TRUSTWORD_NOT_FOUND                         = 0x0501,
    PEP_TRUSTWORDS_FPR_WRONG_LENGTH                 = 0x0502,
    PEP_TRUSTWORDS_DUPLICATE_FPR                    = 0x0503,

    PEP_CANNOT_CREATE_KEY                           = 0x0601,
    PEP_CANNOT_SEND_KEY                             = 0x0602,

    PEP_PHRASE_NOT_FOUND                            = 0x0701,

    PEP_SEND_FUNCTION_NOT_REGISTERED                = 0x0801,
    PEP_CONTRAINTS_VIOLATED                         = 0x0802,
    PEP_CANNOT_ENCODE                               = 0x0803,

    PEP_SYNC_NO_NOTIFY_CALLBACK                     = 0x0901,
    PEP_SYNC_ILLEGAL_MESSAGE                        = 0x0902,
    PEP_SYNC_NO_INJECT_CALLBACK                     = 0x0903,
    PEP_SYNC_NO_CHANNEL                             = 0x0904,
    PEP_SYNC_CANNOT_ENCRYPT                         = 0x0905,
    PEP_SYNC_NO_MESSAGE_SEND_CALLBACK               = 0x0906,
    PEP_SYNC_CANNOT_START                           = 0x0907,

    PEP_CANNOT_INCREASE_SEQUENCE                    = 0x0971,

    PEP_STATEMACHINE_ERROR                          = 0x0980,
    PEP_NO_TRUST                                    = 0x0981,
    PEP_STATEMACHINE_INVALID_STATE                  = 0x0982,
    PEP_STATEMACHINE_INVALID_EVENT                  = 0x0983,
    PEP_STATEMACHINE_INVALID_CONDITION              = 0x0984,
    PEP_STATEMACHINE_INVALID_ACTION                 = 0x0985,
    PEP_STATEMACHINE_INHIBITED_EVENT                = 0x0986,
    PEP_STATEMACHINE_CANNOT_SEND                    = 0x0987,

    PEP_PASSPHRASE_REQUIRED                         = 0x0a00,
    PEP_WRONG_PASSPHRASE                            = 0x0a01,
    PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED            = 0x0a02,

    PEP_DISTRIBUTION_ILLEGAL_MESSAGE                = 0x1002,

    PEP_COMMIT_FAILED                               = 0xff01,
    PEP_MESSAGE_CONSUME                             = 0xff02,
    PEP_MESSAGE_IGNORE                              = 0xff03,
    PEP_CANNOT_CONFIG                               = 0xff04,

    PEP_RECORD_NOT_FOUND                            = -6,
    PEP_CANNOT_CREATE_TEMP_FILE                     = -5,
    PEP_ILLEGAL_VALUE                               = -4,
    PEP_BUFFER_TOO_SMALL                            = -3,
    PEP_OUT_OF_MEMORY                               = -2,
    PEP_UNKNOWN_ERROR                               = -1,
    
    PEP_VERSION_MISMATCH                            = -7,
} PEP_STATUS;

typedef enum _PEP_enc_format {
    PEP_enc_none = 0,                       // message is not encrypted
    PEP_enc_pieces = 1,                     // inline PGP + PGP extensions, was removed
    PEP_enc_inline = 1,                     // still there
    PEP_enc_S_MIME,                         // RFC5751
    PEP_enc_PGP_MIME,                       // RFC3156
    PEP_enc_PEP,                            // pEp encryption format
    PEP_enc_PGP_MIME_Outlook1,              // Message B0rken by Outlook type 1
    PEP_enc_inline_EA,
    PEP_enc_auto = 255                      // figure out automatically where possible
} PEP_enc_format;


// messageToSend() - a message needs to be delivered by application
//
//  parameters:
//      msg (in)        message struct with message to send
//
//  return value:
//      PEP_STATUS_OK or any other value on error
//
//  caveat:
//      the ownership of msg goes to the callee

struct _message;
typedef PEP_STATUS (*messageToSend_t)(struct _message *msg);


struct Sync_event;
typedef struct Sync_event *SYNC_EVENT;

// free_Sync_event() - free memory occupied by sync protocol message
//
//  parameters:
//      ev (in)         event to free

DYNAMIC_API void free_Sync_event(SYNC_EVENT ev);


// inject_sync_event - inject sync protocol message
//
//  parameters:
//      ev (in)             event to inject
//      management (in)     application defined; usually a locked queue
//
//  return value:
//      0 if event could be stored successfully or nonzero otherwise
//
//  caveat:
//      if ev is SHUTDOWN then the implementation has to be synchronous
//      and the shutdown must be immediate

typedef int (*inject_sync_event_t)(SYNC_EVENT ev, void *management);

// ensure_passphrase() - callee ensures correct password for (signing) key is configured in the session on
//                        return, or returns error when it is not found
//  parameters:
//.     session (in)      session for which the guarantee is made
//      fpr (in)          fpr to check
//
//  return value:
//      PEP_STATUS_OK passphrase is configured and ready to use
//      If the caller runs out of passphrases to try, PEP_*PASSWORD* errors 
//      are acceptable.
//.     Other errors if, e.g., the key is not found
//
//  caveat:
//      The callee is responsible for iterating through passwords
//      to ensure signing/encryption can occur successfully. 
//
typedef PEP_STATUS (*ensure_passphrase_t)(PEP_SESSION session, const char* fpr);


// INIT_STATUS init() - initialize pEpEngine for a thread
//
//  parameters:
//      session (out)                       init() allocates session memory and
//                                          returns a pointer as a handle
//      messageToSend (in)                  callback for sending message by the
//                                          application
//      inject_sync_event (in)              callback for injecting a sync event
//      ensure_passphrase (in)             callback for ensuring correct password for key is set
//
//  return value:
//      PEP_STATUS_OK = 0                   if init() succeeds
//      PEP_INIT_SQLITE3_WITHOUT_MUTEX      if SQLite3 was compiled with
//                                          SQLITE_THREADSAFE 0
//      PEP_INIT_CANNOT_LOAD_CRYPTO_LIB     if crypto lin cannot be found
//      PEP_INIT_CRYPTO_LIB_INIT_FAILED     if CRYPTO_LIB init fails
//      PEP_INIT_CANNOT_OPEN_DB             if user's management db cannot be
//                                          opened
//      PEP_INIT_CANNOT_OPEN_SYSTEM_DB      if system's management db cannot be
//                                          opened
//
//  caveat:
//      THE CALLER MUST GUARD THIS CALL EXTERNALLY WITH A MUTEX. release()
//      should be similarly guarded.
//
//      the pointer is valid only if the return value is PEP_STATUS_OK
//      in other case a NULL pointer will be returned; a valid handle must
//      be released using release() when it's no longer needed
//
//      the caller has to guarantee that the first call to this function
//      will succeed before further calls can be done
//
//      messageToSend can only be null if no transport is application based
//      if transport system is not used it must not be NULL
//
//      ensure_refresh_key should only be NULL if the 
//      caller can guarantee that there is only one single or zero passphrases 
//      used in the whole of the keys database

DYNAMIC_API PEP_STATUS init(
        PEP_SESSION *session,
        messageToSend_t messageToSend,
        inject_sync_event_t inject_sync_event,
        ensure_passphrase_t ensure_passphrase
    );



// void release() - release thread session handle
//
//  parameters:
//        session (in)    session handle to release
//
//    caveat:
//        THE CALLER MUST GUARD THIS CALL EXTERNALLY WITH A MUTEX. init() should
//        be similarly guarded.
//       
//        the last release() can be called only when all other release() calls
//        are done

DYNAMIC_API void release(PEP_SESSION session);

// config_passive_mode() - enable passive mode
//
//  parameters:
//      session (in)    session handle
//      enable (in)     flag if enabled or disabled

DYNAMIC_API void config_passive_mode(PEP_SESSION session, bool enable);


// config_unencrypted_subject() - disable subject encryption
//
//  parameters:
//      session (in)    session handle
//      enable (in)     flag if enabled or disabled

DYNAMIC_API void config_unencrypted_subject(PEP_SESSION session, bool enable);


// config_use_only_own_private_keys() - enable passive mode
//
//  parameters:
//      session (in)    session handle
//      enable (in)     flag if enabled or disabled

DYNAMIC_API void config_use_only_own_private_keys(PEP_SESSION session, bool enable);


// config_service_log() - log more for service purposes
//
//      session (in)    session handle
//      enable (in)     flag if enabled or disabled

DYNAMIC_API void config_service_log(PEP_SESSION session, bool enable);

DYNAMIC_API void config_key_election_disabled(PEP_SESSION session, bool disable);

typedef enum {
    PEP_CIPHER_SUITE_DEFAULT = 0,
    PEP_CIPHER_SUITE_CV25519 = 1,
    PEP_CIPHER_SUITE_P256 = 2,
    PEP_CIPHER_SUITE_P384 = 3,
    PEP_CIPHER_SUITE_P521 = 4,
    PEP_CIPHER_SUITE_RSA2K = 5,
    PEP_CIPHER_SUITE_RSA3K = 6,
    PEP_CIPHER_SUITE_RSA4K = 7,
    PEP_CIPHER_SUITE_RSA8K = 8
} PEP_CIPHER_SUITE;

// config_cipher_suite() - cipher suite being used when encrypting
//
//  parameters:
//      session (in)            session handle
//      cipher_suite (in)       cipher suite to use
//
//  return value:
//      PEP_STATUS_OK           cipher suite configured
//      PEP_CANNOT_CONFIG       configuration failed; falling back to default
//
//  caveat: the default ciphersuite for a crypt tech implementation is
//  implementation defined

DYNAMIC_API PEP_STATUS config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);


// decrypt_and_verify() - decrypt and/or verify a message
//
//    parameters:
//        session (in)          session handle
//        ctext (in)            cipher text to decrypt and/or verify
//        csize (in)            size of cipher text
//        dsigtext (in)         if extant, *detached* signature text for this
//                              message (or NULL if not)
//        dsize (in)            size of *detached* signature text for this
//                              message (0, if no detached sig exists)
//        ptext (out)           pointer to internal buffer with plain text
//        psize (out)           size of plain text
//        keylist (out)         list of key ids which where used to encrypt
//        filename_ptr (out)    mails produced by certain PGP implementations 
//                              may return a decrypted filename here for attachments. 
//                              Externally, this can generally be NULL, and is an optional
//                              parameter.
//
//    return value:
//        PEP_UNENCRYPTED               message was unencrypted and not signed
//        PEP_VERIFIED                  message was unencrypted, signature matches
//        PEP_DECRYPTED                 message is decrypted now, no signature
//        PEP_DECRYPTED_AND_VERIFIED    message is decrypted now and verified
//        PEP_DECRYPT_WRONG_FORMAT      message has wrong format to handle
//        PEP_DECRYPT_NO_KEY            key not available to decrypt and/or verify
//        PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH    wrong signature
//
//    caveat:
//        the ownerships of ptext as well as keylist are going to the caller
//        the caller must use free() (or an Windoze pEp_free()) and
//        free_stringlist() to free them
//
//      if this function failes an error message may be the first element of
//      keylist and the other elements may be the keys used for encryption

DYNAMIC_API PEP_STATUS decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char ** filename_ptr
    );


// verify_text() - verfy plain text with a digital signature
//
//  parameters:
//      session (in)    session handle
//      text (in)       text to verify
//      size (in)       size of text
//      signature (in)  signature text
//      sig_size (in)   size of signature
//      keylist (out)   list of key ids which where used to encrypt or NULL on
//                        error
//
//  return value:
//        PEP_VERIFIED                message was unencrypted, signature matches
//        PEP_DECRYPT_NO_KEY          key not available to decrypt and/or verify
//        PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH    wrong signature

DYNAMIC_API PEP_STATUS verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );


// encrypt_and_sign() - encrypt and sign a message
//
//    parameters:
//        session (in)    session handle
//        keylist (in)    list of key ids to encrypt with as C strings
//        ptext (in)      plain text to decrypt and/or verify
//        psize (in)      size of plain text
//        ctext (out)     pointer to internal buffer with cipher text
//        csize (out)     size of cipher text
//
//    return value:
//        PEP_STATUS_OK = 0            encryption and signing succeeded
//        PEP_KEY_NOT_FOUND            at least one of the recipient keys
//                                     could not be found
//        PEP_KEY_HAS_AMBIG_NAME       at least one of the recipient keys has
//                                     an ambiguous name
//        PEP_GET_KEY_FAILED           cannot retrieve key
//
//    caveat:
//      the ownership of ctext is going to the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())
//      the first key in keylist is being used to sign the message
//      this implies there has to be a private key for that keypair

DYNAMIC_API PEP_STATUS encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

DYNAMIC_API void set_debug_color(PEP_SESSION session, int ansi_color);

// log_event() - log a user defined event defined by UTF-8 encoded strings into
// management log
//
//    parameters:
//        session (in)        session handle
//        title (in)          C string with event name
//        entity (in)         C string with name of entity which is logging
//        description (in)    C string with long description for event or NULL if
//                            omitted
//        comment (in)        C string with user defined comment or NULL if
//                            omitted
//
//    return value:
//        PEP_STATUS_OK       log entry created

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session,
        const char *title,
        const char *entity,
        const char *description,
        const char *comment
    );


DYNAMIC_API PEP_STATUS log_service(PEP_SESSION session, const char *title,
        const char *entity, const char *description, const char *comment);

#define _STR_(x) #x
#define _D_STR_(x) _STR_(x)
#define S_LINE _D_STR_(__LINE__)

#define SERVICE_LOG(session, title, entity, desc) \
    log_service((session), (title), (entity), (desc), "service " __FILE__ ":" S_LINE)

DYNAMIC_API void _service_error_log(PEP_SESSION session, const char *entity,
        PEP_STATUS status, const char *where);

#define SERVICE_ERROR_LOG(session, entity, status) \
    _service_error_log((session), (entity), (status), __FILE__ ":" S_LINE)

// trustword() - get the corresponding trustword for a 16 bit value
//
//    parameters:
//        session (in)            session handle
//        value (in)              value to find a trustword for
//        lang (in)               C string with ISO 639-1 language code
//        word (out)              pointer to C string with trustword UTF-8 encoded
//                                NULL if language is not supported or trustword
//                                wordlist is damaged or unavailable
//        wsize (out)             length of trustword
//
//    return value:
//        PEP_STATUS_OK            trustword retrieved
//        PEP_TRUSTWORD_NOT_FOUND  trustword not found
//
//    caveat:
//        the word pointer goes to the ownership of the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())

DYNAMIC_API PEP_STATUS trustword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        );


// trustwords() - get trustwords for a string of hex values of a fingerprint
//
//    parameters:
//        session (in)        session handle
//        fingerprint (in)    C string with hex values to find trustwords for
//        lang (in)           C string with ISO 639-1 language code
//        words (out)         pointer to C string with trustwords UTF-8 encoded,
//                            separated by a blank each
//                            NULL if language is not supported or trustword
//                            wordlist is damaged or unavailable
//        wsize (out)         length of trustwords string
//        max_words (in)      only generate a string with max_words;
//                            if max_words == 0 there is no such limit
//
//    return value:
//        PEP_STATUS_OK            trustwords retrieved
//        PEP_OUT_OF_MEMORY        out of memory
//        PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
//
//    caveat:
//        the word pointer goes to the ownership of the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())
//
//  DON'T USE THIS FUNCTION FROM HIGH LEVEL LANGUAGES!
//
//  Better implement a simple one in the adapter yourself using trustword(), and
//  return a list of trustwords.
//  This function is provided for being used by C and C++ programs only.

DYNAMIC_API PEP_STATUS trustwords(
        PEP_SESSION session, const char *fingerprint, const char *lang,
        char **words, size_t *wsize, int max_words
    );


// TODO: increase versions in pEp.asn1 if rating changes

typedef enum _PEP_comm_type {
    PEP_ct_unknown = 0,

    // range 0x01 to 0x09: no encryption, 0x0a to 0x0e: nothing reasonable

    PEP_ct_no_encryption = 0x01,                // generic
    PEP_ct_no_encrypted_channel = 0x02,
    PEP_ct_key_not_found = 0x03,
    PEP_ct_key_expired = 0x04,
    PEP_ct_key_revoked = 0x05,
    PEP_ct_key_b0rken = 0x06,
    PEP_ct_key_expired_but_confirmed = 0x07, // NOT with confirmed bit. Just retaining info here in case of renewal.
    PEP_ct_my_key_not_included = 0x09,

    PEP_ct_security_by_obscurity = 0x0a,
    PEP_ct_b0rken_crypto = 0x0b,
    PEP_ct_key_too_short = 0x0c,

    PEP_ct_compromised = 0x0e,                  // known compromised connection
    PEP_ct_compromized = 0x0e,                  // deprecated misspelling
    PEP_ct_mistrusted = 0x0f,                   // known mistrusted key

    // range 0x10 to 0x3f: unconfirmed encryption

    PEP_ct_unconfirmed_encryption = 0x10,       // generic
    PEP_ct_OpenPGP_weak_unconfirmed = 0x11,     // RSA 1024 is weak

    PEP_ct_to_be_checked = 0x20,                // generic
    PEP_ct_SMIME_unconfirmed = 0x21,
    PEP_ct_CMS_unconfirmed = 0x22,

    PEP_ct_strong_but_unconfirmed = 0x30,       // generic
    PEP_ct_OpenPGP_unconfirmed = 0x38,          // key at least 2048 bit RSA or EC
    PEP_ct_OTR_unconfirmed = 0x3a,

    // range 0x40 to 0x7f: unconfirmed encryption and anonymization

    PEP_ct_unconfirmed_enc_anon = 0x40,         // generic
    PEP_ct_pEp_unconfirmed = 0x7f,

    PEP_ct_confirmed = 0x80,                    // this bit decides if trust is confirmed

    // range 0x81 to 0x8f: reserved
    // range 0x90 to 0xbf: confirmed encryption

    PEP_ct_confirmed_encryption = 0x90,         // generic
    PEP_ct_OpenPGP_weak = 0x91,                 // RSA 1024 is weak (unused)

    PEP_ct_to_be_checked_confirmed = 0xa0,      // generic
    PEP_ct_SMIME = 0xa1,
    PEP_ct_CMS = 0xa2,

    PEP_ct_strong_encryption = 0xb0,            // generic
    PEP_ct_OpenPGP = 0xb8,                      // key at least 2048 bit RSA or EC
    PEP_ct_OTR = 0xba,

    // range 0xc0 to 0xff: confirmed encryption and anonymization

    PEP_ct_confirmed_enc_anon = 0xc0,           // generic
    PEP_ct_pEp = 0xff
} PEP_comm_type;

typedef enum _identity_flags {
    // the first octet flags are app defined settings
    PEP_idf_not_for_sync = 0x0001,   // don't use this identity for sync
    PEP_idf_list = 0x0002,           // identity of list of persons
    // the second octet flags are calculated
    PEP_idf_devicegroup = 0x0100     // identity of a device group member
} identity_flags;

typedef unsigned int identity_flags_t;

// typedef enum _keypair_flags {
// } keypair_flags;

typedef unsigned int keypair_flags_t;

typedef struct _pEp_identity {
    char *address;              // C string with address UTF-8 encoded
    char *fpr;                  // C string with fingerprint UTF-8 encoded
    char *user_id;              // C string with user ID UTF-8 encoded
                                // user_id MIGHT be set to "pEp_own_userId"
                                // (use PEP_OWN_USERID preprocessor define)
                                // if this is own user's identity.
                                // But it is not REQUIRED to be.
    char *username;             // C string with user name UTF-8 encoded
    PEP_comm_type comm_type;    // type of communication with this ID
    char lang[3];               // language of conversation
                                // ISO 639-1 ALPHA-2, last byte is 0
    bool me;                    // if this is the local user herself/himself
    unsigned int major_ver;     // highest version of pEp message received, if any
    unsigned int minor_ver;     // highest version of pEp message received, if any
    PEP_enc_format enc_format;  // Last specified format we encrypted to for this identity
    identity_flags_t flags;     // identity_flag1 | identity_flag2 | ...
} pEp_identity;

typedef struct _identity_list {
    pEp_identity *ident;
    struct _identity_list *next;
} identity_list;


// new_identity() - allocate memory and set the string and size fields
//
//  parameters:
//      address (in)        UTF-8 string or NULL 
//      fpr (in)            UTF-8 string or NULL 
//      user_id (in)        UTF-8 string or NULL 
//      username (in)       UTF-8 string or NULL 
//
//  return value:
//      pEp_identity struct or NULL if out of memory
//
//  caveat:
//      the strings are copied; the original strings are still being owned by
//      the caller

DYNAMIC_API pEp_identity *new_identity(
        const char *address, const char *fpr, const char *user_id,
        const char *username
    );


// identity_dup() - allocate memory and duplicate
//
//  parameters:
//      src (in)            identity to duplicate
//
//  return value:
//      pEp_identity struct or NULL if out of memory
//
//  caveat:
//      the strings are copied; the original strings are still being owned by
//      the caller

DYNAMIC_API pEp_identity *identity_dup(const pEp_identity *src);


// free_identity() - free all memory being occupied by a pEp_identity struct
//
//  parameters:
//      identity (in)       struct to release
//
//  caveat:
//      not only the struct but also all string memory referenced by the
//      struct is being freed; all pointers inside are invalid afterwards

DYNAMIC_API void free_identity(pEp_identity *identity);


// get_identity() - get identity information
//
//    parameters:
//        session (in)        session handle
//        address (in)        C string with communication address, UTF-8 encoded
//        user_id (in)        unique C string to identify person that identity
//                            is refering to
//        identity (out)      pointer to pEp_identity structure with results or
//                            NULL if failure
//
//    caveat:
//        address and user_id are being copied; the original strings remains in
//        the ownership of the caller
//        the resulting pEp_identity structure goes to the ownership of the
//        caller and has to be freed with free_identity() when not in use any
//        more

DYNAMIC_API PEP_STATUS get_identity(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    );

PEP_STATUS replace_identities_fpr(PEP_SESSION session, 
                                 const char* old_fpr, 
                                 const char* new_fpr); 


// set_identity() - set identity information
//
//    parameters:
//        session (in)        session handle
//        identity (in)       pointer to pEp_identity structure
//
//    return value:
//        PEP_STATUS_OK = 0             encryption and signing succeeded
//        PEP_CANNOT_SET_PERSON         writing to table person failed
//        PEP_CANNOT_SET_PGP_KEYPAIR    writing to table pgp_keypair failed
//        PEP_CANNOT_SET_IDENTITY       writing to table identity failed
//        PEP_COMMIT_FAILED             SQL commit failed
//
//    caveat:
//        address, fpr, user_id and username must be given

DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    );

// get_default own_userid() - get the user_id of the own user
//
//    parameters:
//        session (in)        session handle
//        userid  (out)       own user id (if it exists)
//
//    return value:
//        PEP_STATUS_OK = 0             userid was found
//        PEP_CANNOT_FIND_IDENTITY      no own_user found in the DB
//        PEP_UNKNOWN_ERROR             results were returned, but no ID
//                                      found (no reason this should ever occur)
//    caveat:
//        userid will be NULL if not found; otherwise, returned string
//        belongs to the caller.

DYNAMIC_API PEP_STATUS get_default_own_userid(
        PEP_SESSION session, 
        char** userid
    );

// get_userid_alias_default() - get the default user_id which corresponds
//                              to an alias
//    parameters:
//        session (in)        session handle
//        alias_id (in)       the user_id which may be an alias for a default id
//        default_id (out)    the default id for this alias, if the alias
//                            is in the DB as an alias, else NULL
//    return value:
//        PEP_STATUS_OK = 0             userid was found
//        PEP_CANNOT_FIND_ALIAS         this userid is not listed as an 
//                                      alias in the DB
//        PEP_UNKNOWN_ERROR             results were returned, but no ID
//                                      found (no reason this should ever occur)
//    caveat:
//        default_id will be NULL if not found; otherwise, returned string
//        belongs to the caller.
//        also, current implementation does NOT check to see if this userid
//        IS a default.

DYNAMIC_API PEP_STATUS get_userid_alias_default(
        PEP_SESSION session, 
        const char* alias_id,
        char** default_id);

// set_userid_alias() - set an alias to correspond to a default id
//    parameters:
//        session (in)        session handle
//        default_id (in)     the default id for this alias. This must
//                            correspond to the default user_id for an
//                            entry in the person (user) table.
//        alias_id (in)       the alias to be set for this default id
//    return value:
//        PEP_STATUS_OK = 0             userid was found
//        PEP_CANNOT_SET_ALIAS          there was an error setting this

DYNAMIC_API PEP_STATUS set_userid_alias (
        PEP_SESSION session, 
        const char* default_id,
        const char* alias_id);

// set_identity_flags() - update identity flags on existing identity
//
//    parameters:
//        session (in)        session handle
//        identity (in,out)   pointer to pEp_identity structure
//        flags (in)          new value for flags
//
//    return value:
//        PEP_STATUS_OK = 0             encryption and signing succeeded
//        PEP_CANNOT_SET_IDENTITY       update of identity failed
//
//    caveat:
//        address and user_id must be given in identity

DYNAMIC_API PEP_STATUS set_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        identity_flags_t flags
    );

// unset_identity_flags() - update identity flags on existing identity
//
//    parameters:
//        session (in)        session handle
//        identity (in,out)   pointer to pEp_identity structure
//        flags (in)          new value for flags
//
//    return value:
//        PEP_STATUS_OK = 0             encryption and signing succeeded
//        PEP_CANNOT_SET_IDENTITY       update of identity failed
//
//    caveat:
//        address and user_id must be given in identity

DYNAMIC_API PEP_STATUS unset_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        identity_flags_t flags
    );

// mark_as_compromised() - mark key in trust db as compromised
//
//    parameters:
//        session (in)        session handle
//        fpr (in)            fingerprint of key to mark

DYNAMIC_API PEP_STATUS mark_as_compromised(
        PEP_SESSION session,
        const char *fpr
    );


// mark_as_compromized() - deprecated to fix misspelling. Please move to
//                         mark_as_compromised();

DYNAMIC_API PEP_STATUS mark_as_compromized(
        PEP_SESSION session,
        const char *fpr
    );


// generate_keypair() - generate a new key pair and add it to the key ring
//
//  parameters:
//      session (in)            session handle
//        identity (inout)      pointer to pEp_identity structure
//
//    return value:
//        PEP_STATUS_OK = 0       encryption and signing succeeded
//        PEP_ILLEGAL_VALUE       illegal values for identity fields given
//        PEP_CANNOT_CREATE_KEY   key engine is on strike
//
//  caveat:
//      address must be set to UTF-8 string
//      the fpr field must be set to NULL
//      username field must either be NULL or be a UTF8-string conforming 
//      to RFC4880 for PGP uid usernames  
//
//      this function allocates a string and sets set fpr field of identity
//      the caller is responsible to call free() for that string or use
//      free_identity() on the struct

DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    );


// delete_keypair() - delete a public key or a key pair from the key ring
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                C string with key id or fingerprint of the
//                              public key
//
//  return value:
//      PEP_STATUS_OK = 0       key was successfully deleted
//      PEP_KEY_NOT_FOUND       key not found
//      PEP_ILLEGAL_VALUE       not a valid key id or fingerprint
//      PEP_KEY_HAS_AMBIG_NAME  fpr does not uniquely identify a key
//      PEP_OUT_OF_MEMORY       out of memory

DYNAMIC_API PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr);


// import_key() - import key from data
//
//  parameters:
//      session (in)                session handle
//      key_data (in)               key data, i.e. ASCII armored OpenPGP key
//      size (in)                   amount of data to handle
//      private_keys (out)          list of identities containing the 
//                                  private keys that have been imported
//
//  return value:
//      PEP_STATUS_OK = 0       key was successfully imported
//      PEP_OUT_OF_MEMORY       out of memory
//      PEP_ILLEGAL_VALUE       there is no key data to import
//
//  caveat:
//      private_keys goes to the ownership of the caller
//      private_keys can be left NULL, it is then ignored

DYNAMIC_API PEP_STATUS import_key(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_keys       
    );

// import_key_with_fpr_return() - 
//                import keys from data, return optional list of fprs imported
//
//  parameters:
//      session (in)                session handle
//      key_data (in)               key data, i.e. ASCII armored OpenPGP key
//      size (in)                   amount of data to handle
//      private_keys (out)          list of identities containing the 
//                                  private keys that have been imported
//      imported_keys (out)         if non-NULL, list of actual keys imported
//      changed_public_keys (out)   if non-NULL AND imported_keys is non-NULL:
//                                  bitvector - corresponds to the first 64 keys
//                                  imported. If nth bit is set, import changed a
//                                  key corresponding to the nth element in
//                                  imported keys (i.e. key was in DB and was
//                                  changed by import)
//
//  return value:
//      PEP_STATUS_OK = 0       key was successfully imported
//      PEP_OUT_OF_MEMORY       out of memory
//      PEP_ILLEGAL_VALUE       there is no key data to import, or imported keys was NULL and 
//                              changed_public_keys was not
//
//  caveat:
//      private_keys and imported_keys goes to the ownership of the caller
//      private_keys and imported_keys can be left NULL, it is then ignored
//      *** THIS IS THE ACTUAL FUNCTION IMPLEMENTED BY CRYPTOTECH "import_key" ***

DYNAMIC_API PEP_STATUS import_key_with_fpr_return(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list** private_keys,
        stringlist_t** imported_keys,
        uint64_t* changed_public_keys // use as bit field for the first 64 changed keys
);


// export_key() - export ascii armored key
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                key id or fingerprint of key
//      key_data (out)          ASCII armored OpenPGP key
//      size (out)              amount of data to handle
//
//  return value:
//      PEP_STATUS_OK = 0       key was successfully exported
//      PEP_OUT_OF_MEMORY       out of memory
//      PEP_KEY_NOT_FOUND       key not found
//
//  caveat:
//      the key_data goes to the ownership of the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())

DYNAMIC_API PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );


// export_secret_key() - export secret key ascii armored
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key, at least 16 hex digits
//      key_data (out)          ASCII armored OpenPGP secret key
//      size (out)              amount of data to handle
//
//  return value:
//      PEP_STATUS_OK = 0       key was successfully exported
//      PEP_OUT_OF_MEMORY       out of memory
//      PEP_KEY_NOT_FOUND       key not found
//      PEP_CANNOT_EXPORT_KEY   cannot export secret key (i.e. it's on an HKS)
//
//  caveat:
//      the key_data goes to the ownership of the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())
//      beware of leaking secret key data - overwrite it in memory after use

DYNAMIC_API PEP_STATUS export_secret_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );


// export_secrect_key() - deprecated misspelled function. Please replace with
//                        export_secret_key

DYNAMIC_API PEP_STATUS export_secrect_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );


// recv_key() - update key(s) from keyserver
//
//  parameters:
//      session (in)            session handle
//      pattern (in)            key id, user id or address to search for as
//                              UTF-8 string

DYNAMIC_API PEP_STATUS recv_key(PEP_SESSION session, const char *pattern);


// find_keys() - find keys in keyring
//
//  parameters:
//      session (in)            session handle
//      pattern (in)            key id, user id or address to search for as
//                              UTF-8 string
//      keylist (out)           list of fingerprints found or NULL on error
//
//  caveat:
//        the ownerships of keylist isgoing to the caller
//        the caller must use free_stringlist() to free it


DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

// send_key() - send key(s) to keyserver
//
//  parameters:
//      session (in)            session handle
//      pattern (in)            key id, user id or address to search for as
//                              UTF-8 string

DYNAMIC_API PEP_STATUS send_key(PEP_SESSION session, const char *pattern);


// pEp_free() - free memory allocated by pEp engine
//
//  parameters:
//      p (in)                  pointer to free
//
//  The reason for this function is that heap management can be a pretty
//  complex task with Windoze. This free() version calls the free()
//  implementation of the C runtime library which was used to build pEp engine,
//  so you're using the correct heap. For more information, see:
//  <http://msdn.microsoft.com/en-us/library/windows/desktop/aa366711(v=vs.85).aspx>

DYNAMIC_API void pEp_free(void *p);


// pEp_realloc() - reallocate memory allocated by pEp engine
//
//  parameters:
//      p (in)                  pointer to free
//      size (in)               new memory size
//
//  returns:
//      pointer to allocated memory
//
//  The reason for this function is that heap management can be a pretty
//  complex task with Windoze. This realloc() version calls the realloc()
//  implementation of the C runtime library which was used to build pEp engine,
//  so you're using the correct heap. For more information, see:
//  <http://msdn.microsoft.com/en-us/library/windows/desktop/aa366711(v=vs.85).aspx>

DYNAMIC_API void *pEp_realloc(void *p, size_t size);


// get_trust() - get the trust level a key has for a person
//
//  parameters:
//      session (in)            session handle
//      identity (inout)        user_id and fpr to check as UTF-8 strings (in)
//                              comm_type as result (out)
//
//  this function modifies the given identity struct; the struct remains in
//  the ownership of the caller
//  if the trust level cannot be determined identity->comm_type is set
//  to PEP_ct_unknown

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity);


PEP_STATUS set_trust(PEP_SESSION session, 
                     pEp_identity* identity);
                            
PEP_STATUS update_trust_for_fpr(PEP_SESSION session, 
                                const char* fpr, 
                                PEP_comm_type comm_type);

// least_trust() - get the least known trust level for a key in the database
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to check
//      comm_type (out)         least comm_type as result (out)
//
//  if the trust level cannot be determined comm_type is set to PEP_ct_unknown

DYNAMIC_API PEP_STATUS least_trust(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );


// get_key_rating() - get the rating a bare key has
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                unique identifyer for key as UTF-8 string
//      comm_type (out)         key rating
//
//  if an error occurs, *comm_type is set to PEP_ct_unknown and an error
//  is returned

DYNAMIC_API PEP_STATUS get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );


// renew_key() - renew an expired key
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                ID of key to renew as UTF-8 string
//      ts (in)                 timestamp when key should expire or NULL for
//                              default

DYNAMIC_API PEP_STATUS renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    );


// revoke_key() - revoke a key
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                ID of key to revoke as UTF-8 string
//      reason (in)             text with reason for revoke as UTF-8 string
//                              or NULL if reason unknown
//
//  caveat:
//      reason text must not include empty lines
//      this function is meant for internal use only; better use
//      key_mistrusted() of keymanagement API

DYNAMIC_API PEP_STATUS revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    );


// key_expired() - flags if a key is already expired
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                ID of key to check as UTF-8 string
//      when (in)               UTC time of when should expiry be considered
//      expired (out)           flag if key expired

DYNAMIC_API PEP_STATUS key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    );

    
// key_revoked() - flags if a key is already revoked
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                ID of key to check as UTF-8 string
//      revoked (out)           flag if key revoked

DYNAMIC_API PEP_STATUS key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    );

PEP_STATUS get_key_userids(
        PEP_SESSION session,
        const char* fpr,
        stringlist_t** keylist
    );


// get_crashdump_log() - get the last log messages out
//
//  parameters:
//      session (in)            session handle
//      maxlines (in)           maximum number of lines (0 for default)
//      logdata (out)           logdata as string in double quoted CSV format
//                              column1 is title
//                              column2 is entity
//                              column3 is description
//                              column4 is comment
//
//  caveat:
//      the ownership of logdata goes to the caller

DYNAMIC_API PEP_STATUS get_crashdump_log(
        PEP_SESSION session,
        int maxlines,
        char **logdata
    );


// get_languagelist() - get the list of languages
//
//  parameters:
//      session (in)            session handle
//      languages (out)         languages as string in double quoted CSV format
//                              column 1 is the ISO 639-1 language code
//                              column 2 is the name of the language
//
//  caveat:
//      the ownership of languages goes to the caller

DYNAMIC_API PEP_STATUS get_languagelist(
        PEP_SESSION session,
        char **languages
    );


// get_phrase() - get phrase in a dedicated language through i18n
//
//  parameters:
//      session (in)            session handle
//      lang (in)               C string with ISO 639-1 language code
//      phrase_id (in)          id of phrase in i18n
//      phrase (out)            phrase as UTF-8 string
//
//  caveat:
//      the ownership of phrase goes to the caller

DYNAMIC_API PEP_STATUS get_phrase(
        PEP_SESSION session,
        const char *lang,
        int phrase_id,
        char **phrase
    );


// sequence_value() - raise the value of a named sequence and retrieve it
//
//  parameters:
//      session (in)            session handle
//      name (in)               name of sequence
//      value (out)             value of sequence
//
//  returns:
//      PEP_STATUS_OK                   no error, not own sequence
//      PEP_SEQUENCE_VIOLATED           if sequence violated
//      PEP_CANNOT_INCREASE_SEQUENCE    if sequence cannot be increased
//      PEP_OWN_SEQUENCE                if own sequence

DYNAMIC_API PEP_STATUS sequence_value(
        PEP_SESSION session,
        const char *name,
        int32_t *value
    );


// set_revoked() - records relation between a revoked key and its replacement
//
//  parameters:
//      session (in)            session handle
//      revoked_fpr (in)        revoked fingerprint
//      replacement_fpr (in)    replacement key fingerprint
//      revocation_date (in)    revocation date

DYNAMIC_API PEP_STATUS set_revoked(
       PEP_SESSION session,
       const char *revoked_fpr,
       const char *replacement_fpr,
       const uint64_t revocation_date
    );


// get_revoked() - find revoked key that may have been replaced by given key, if any
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                given fingerprint
//      revoked_fpr (out)       revoked fingerprint
//      revocation_date (out)   revocation date
    
DYNAMIC_API PEP_STATUS get_revoked(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    );

// key_created() - get creation date of a key
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key
//      created (out)           date of creation

PEP_STATUS key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    );


// find_private_keys() - find keys in keyring
//
//  parameters:
//      session (in)            session handle
//      pattern (in)            key id, user id or address to search for as
//                              UTF-8 string
//      keylist (out)           list of fingerprints found or NULL on error
//
//  caveat:
//        the ownerships of keylist isgoing to the caller
//        the caller must use free_stringlist() to free it
PEP_STATUS find_private_keys(PEP_SESSION session, const char* pattern,
                             stringlist_t **keylist);

// get_engine_version() - returns the current version of pEpEngine (this is different
//                        from the pEp protocol version!)
//
//  parameters: none
//
//  return_value: const char* to the engine version string constant
//
DYNAMIC_API const char* get_engine_version();

// get_protocol_version() - returns the pEp protocol version

DYNAMIC_API const char *get_protocol_version();

// is_pEp_user() - returns true if the USER corresponding to this identity 
//                 has been listed in the *person* table as a pEp user. 
//
//  parameters:
//      identity (in) - identity containing the user_id to check (this is
//                      the only part of the struct we require to be set)
//      is_pEp (out)  - boolean pointer - will return true or false by
//                      reference with respect to whether or not user is
//                      a known pEp user
//
//  return_value: PEP_STATUS_OK if user found in person table
//                PEP_ILLEGAL_VALUE if no user_id in input
//                PEP_CANNOT_FIND_PERSON if user_id doesn't exist
//
//  caveat: This *does not check comm_type*
//                         
DYNAMIC_API PEP_STATUS is_pEp_user(PEP_SESSION session, 
                                   pEp_identity *identity, 
                                   bool* is_pEp);

// per_user_directory() - returns the directory for pEp management db
//
//  return_value:
//      path to actual per user directory or NULL on failure

DYNAMIC_API const char *per_user_directory(void);


// per_machine_directory() - returns the directory for pEp system db
//
//  return value:
//      path to actual per user directory or NULL on failure

DYNAMIC_API const char *per_machine_directory(void);

// FIXME: replace in canonical style
//
// config_passphrase() - configure a key passphrase for the current session.
//
// A passphrase can be configured into a p≡p session. Then it is used whenever a
// secret key is used which requires a passphrase.
// 
// A passphrase is a string between 1 and 1024 bytes and is only ever present in
// memory. Because strings in the p≡p engine are UTF-8 NFC, the string is
// restricted to 250 code points in UI.
// 
// This function copies the passphrase into the session. It may return
// PEP_OUT_OF_MEMORY. The behaviour of all functions which use secret keys may
// change after this is configured.  Error behaviour
// 
// For any function which may trigger the use of a secret key, if an attempt
// to use a secret key which requires a passphrase occurs and no passphrase
// is configured for the current session, PEP_PASSPHRASE_REQUIRED is
// returned by this function (and thus, all functions which could trigger
// such a usage must be prepared to return this value).  For any function
// which may trigger the use of a secret key, if a passphrase is configured
// and the configured passphrase is the wrong passphrase for the use of a
// given passphrase-protected secret key, PEP_WRONG_PASSPHRASE is returned
// by this function (and thus, all functions which could trigger such a
// usage must be prepared to return this value).

DYNAMIC_API PEP_STATUS config_passphrase(PEP_SESSION session, const char *passphrase);

// FIXME: replace in canonical style
//
// Passphrase enablement for newly-generated secret keys
// 
// If it is desired that new p≡p keys are passphrase-protected, the following
// API call is used to enable the addition of passphrases to new keys during key
// generation.
//
// If enabled and a passphrase for new keys has been configured
// through this function (NOT the one above - this is a separate passphrase!),
// then anytime a secret key is generated while enabled, the configured
// passphrase will be used as the passphrase for any newly-generated secret key.
//
// If enabled and a passphrase for new keys has not been configured, then any
// function which can attempt to generate a secret key will return
// PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED.  
//
// If disabled (i.e. not enabled) and a passphrase for new keys has been
// configured, no passphrases will be used for newly-generated keys.
//
// This function copies the passphrase for new keys into a special field that is
// specifically for key generation into the session. It may return
// PEP_OUT_OF_MEMORY. The behaviour of all functions which use secret keys may
// change after this is configured.
//

DYNAMIC_API PEP_STATUS config_passphrase_for_new_keys(PEP_SESSION session, 
                                                      bool enable,
                                                      const char *passphrase);

// set_ident_enc_format() - set the default encryption format for this identity
//                          (value only MIGHT be used, and only in the case where the
//                          message enc_format is PEP_enc_auto. It will be used 
//                          opportunistically in the case on a first-come, first-serve 
//                          basis in the order of to_list, cc_list, and bcc_list. We take 
//                          the first set value we come to)
//
//  parameters:
//      session (in)            session handle
//      identity (in)           identity->user_id and identity->address must NOT be NULL
//      format (in)             the desired default encryption format
//
DYNAMIC_API PEP_STATUS set_ident_enc_format(PEP_SESSION session,
                                            pEp_identity *identity,
                                            PEP_enc_format format);


PEP_STATUS _generate_keypair(PEP_SESSION session, 
                             pEp_identity *identity,
                             bool suppress_event);

// set_comm_partner_key() - Set the default key fingerprint for the identity identitified by this address and user_id.
//
//  parameters:
//      session  (in)            session handle
//      identity (inout)         identity - cannot be NULL
//      fpr      (in)            fingerprint for identity - cannot be NULL or empty
//
DYNAMIC_API PEP_STATUS set_comm_partner_key(PEP_SESSION session,
                                            pEp_identity *identity,
                                            const char* fpr);


// set_default_identity_fpr() - FOR UPPER_LEVEL TESTING ONLY - NOT TO BE USED DIRECTLY BY ADAPTER OR APPS IN PRODUCTION
//                              Set the default key fingerprint for the identity identitified by this address and user_id.
//                              Only to be used for testing, since key election cannot be relied upon for tests.
//  parameters:
//      session (in)            session handle
//      user_id (in)            user_id for identity - cannot be NULL
//      address (in)            address for identity - cannot be NULL
//      fpr     (in)            fingerprint for identity - cannot be NULL
//
PEP_STATUS set_default_identity_fpr(PEP_SESSION session,
                                                const char* user_id,
                                                const char* address,
                                                const char* fpr);

PEP_STATUS get_default_identity_fpr(PEP_SESSION session,
                                    const char* address,
                                    const char* user_id,
                                    char** main_fpr);

DYNAMIC_API PEP_STATUS reset_pEptest_hack(PEP_SESSION session);

// This is used internally when there is a temporary identity to be retrieved
// that may not yet have an FPR attached. See get_identity() for functionality,
// params and caveats.
PEP_STATUS get_identity_without_trust_check(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    );
    
PEP_STATUS get_identities_by_address(
        PEP_SESSION session,
        const char *address,
        identity_list** id_list
    );
    
PEP_STATUS get_identities_by_userid(
        PEP_SESSION session,
        const char *user_id,
        identity_list **identities
    );    
        
PEP_STATUS is_own_address(PEP_SESSION session, 
                          const char* address, 
                          bool* is_own_addr);

PEP_STATUS replace_userid(PEP_SESSION session, const char* old_uid,
                              const char* new_uid);
                              
PEP_STATUS remove_key(PEP_SESSION session, const char* fpr);
                              
PEP_STATUS remove_fpr_as_default(PEP_SESSION session, 
                                    const char* fpr);
                              
                                    
PEP_STATUS get_main_user_fpr(PEP_SESSION session, 
                             const char* user_id,
                             char** main_fpr);

PEP_STATUS replace_main_user_fpr(PEP_SESSION session, const char* user_id,
                              const char* new_fpr);

PEP_STATUS replace_main_user_fpr_if_equal(PEP_SESSION session, const char* user_id,
                                          const char* new_fpr, const char* compare_fpr);
    
DYNAMIC_API PEP_STATUS get_replacement_fpr(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    );
    
PEP_STATUS refresh_userid_default_key(PEP_SESSION session, const char* user_id);

// This ONLY sets the *user* flag, and creates a shell identity if necessary.
DYNAMIC_API PEP_STATUS set_as_pEp_user(PEP_SESSION session, pEp_identity* user);

// returns true (by reference) if a person with this user_id exists; 
// Also replaces aliased user_ids by defaults in identity.
PEP_STATUS exists_person(PEP_SESSION session, pEp_identity* identity, bool* exists);

PEP_STATUS set_pgp_keypair(PEP_SESSION session, const char* fpr);

PEP_STATUS set_pEp_version(PEP_SESSION session, pEp_identity* ident, unsigned int new_ver_major, unsigned int new_ver_minor);
                
PEP_STATUS clear_trust_info(PEP_SESSION session,
                            const char* user_id,
                            const char* fpr);
                            
// Generally ONLY called by set_as_pEp_user, and ONLY from < 2.0 to 2.0.
PEP_STATUS upgrade_pEp_version_by_user_id(PEP_SESSION session, 
        pEp_identity* ident, 
        unsigned int new_ver_major,
        unsigned int new_ver_minor
    );
     
// exposed for testing
PEP_STATUS set_person(PEP_SESSION session, pEp_identity* identity,
                      bool guard_transaction);
PEP_STATUS bind_own_ident_with_contact_ident(PEP_SESSION session,
                                             pEp_identity* own_ident, 
                                             pEp_identity* contact_ident);

PEP_STATUS get_last_contacted(
        PEP_SESSION session,
        identity_list** id_list
    );

PEP_STATUS get_own_ident_for_contact_id(PEP_SESSION session,
                                          const pEp_identity* contact,
                                          pEp_identity** own_ident);

PEP_STATUS exists_trust_entry(PEP_SESSION session, pEp_identity* identity,
                              bool* exists);

PEP_STATUS is_own_key(PEP_SESSION session, const char* fpr, bool* own_key);

PEP_STATUS get_identities_by_main_key_id(
        PEP_SESSION session,
        const char *fpr,
        identity_list **identities);
        
PEP_STATUS sign_only(PEP_SESSION session, 
                     const char *data, 
                     size_t data_size, 
                     const char *fpr, 
                     char **sign, 
                     size_t *sign_size);
                     
PEP_STATUS set_all_userids_to_own(PEP_SESSION session, 
                                  identity_list* id_list);

PEP_STATUS has_partner_contacted_address(PEP_SESSION session, const char* partner_id,
                                         const char* own_address, bool* was_contacted);
                                                                                  
#ifdef __cplusplus
}
#endif
#endif
