/** 
 * @file    pEpEngine.h
 * @brief   pEp Engine API, as well as exposed internal functions and structures. (The latter should probably be factored out at some point) 
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

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

#define PEP_VERSION "2.2" // pEp *protocol* version

// RELEASE version this targets
// (string: major.minor.patch)
#define PEP_ENGINE_VERSION "3.2.0"
#define PEP_ENGINE_VERSION_MAJOR 3
#define PEP_ENGINE_VERSION_MINOR 2
#define PEP_ENGINE_VERSION_PATCH 0
#define PEP_ENGINE_VERSION_RC    1


#define PEP_OWN_USERID "pEp_own_userId"
    
// pEp Engine API

//  caveat:
//      Unicode data has to be normalized to NFC before calling
//      UTF-8 strings are UTF-8 encoded C strings (zero terminated)


struct _pEpSession;
typedef struct _pEpSession * PEP_SESSION;

/**
 *  @enum    PEP_STATUS
 *  
 *  @brief    TODO
 *  
 */
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
    PEP_NO_OWN_USERID_FOUND                         = 0x0393,
    
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
    PEP_VERFIY_DIFFERENT_KEYS                       = 0x040b,
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

    PEP_CANNOT_CREATE_GROUP                         = 0x0b00,
    PEP_CANNOT_FIND_GROUP_ENTRY                     = 0x0b01,
    PEP_GROUP_EXISTS                                = 0x0b02,
    PEP_GROUP_NOT_FOUND                             = 0x0b03,
    PEP_CANNOT_ENABLE_GROUP                         = 0x0b04,
    PEP_CANNOT_DISABLE_GROUP                        = 0x0b05,
    PEP_CANNOT_ADD_GROUP_MEMBER                     = 0x0b06,
    PEP_CANNOT_DEACTIVATE_GROUP_MEMBER              = 0x0b07,
    PEP_NO_MEMBERSHIP_STATUS_FOUND                  = 0x0b08,
    PEP_CANNOT_LEAVE_GROUP                          = 0x0b09,
    PEP_CANNOT_JOIN_GROUP                           = 0x0b0a,
    PEP_CANNOT_RETRIEVE_MEMBERSHIP_INFO             = 0x0b0b,

    PEP_DISTRIBUTION_ILLEGAL_MESSAGE                = 0x1002,
    PEP_STORAGE_ILLEGAL_MESSAGE                     = 0x1102,

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

/**
 *  @enum    PEP_enc_format
 *  
 *  @brief    TODO
 *  
 */
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


/**
 *  <!--       messageToSend()       -->
 *  
 *  @brief A message needs to be delivered by application
 *  
 *  @param[in]   msg    message struct with message to send
 *  
 *  @retval PEP_STATUS_OK or any other value on error
 *  
 *  @warning the ownership of msg goes to the callee
 *  
 */

struct _message;
typedef PEP_STATUS (*messageToSend_t)(struct _message *msg);


struct Sync_event;
typedef struct Sync_event *SYNC_EVENT;

/**
 *  <!--       free_Sync_event()       -->
 *  
 *  @brief Free memory occupied by sync protocol message
 *  
 *  @param[in]   ev    event to free
 *  
 *  
 */

DYNAMIC_API void free_Sync_event(SYNC_EVENT ev);


/**
 *  <!--       inject_sync_event()       -->
 *  
 *  @brief Inject sync protocol message
 *  
 *  @param[in]   ev            event to inject
 *  @param[in]   management    application defined; usually a locked queue
 *  
 *  @retval 0           if event could be stored successfully 
 *  @retval nonzero     otherwise
 *  
 *  @warning if ev is SHUTDOWN then the implementation has to be synchronous
 *           and the shutdown must be immediate
 *  
 */

typedef int (*inject_sync_event_t)(SYNC_EVENT ev, void *management);

/**
 *  <!--       ensure_passphrase()       -->
 *  
 *  @brief Callee ensures correct password for (signing) key is configured in the session on
 *         return, or returns error when it is not found
 *  
 *  @param[in]   fpr    fpr to check
 *  
 *  @retval PEP_STATUS_OK       passphrase is configured and ready to use
 *  @retval PEP_PASSPHRASE*     If the caller runs out of passphrases to try, PEP_*PASSWORD* errors 
 *                              are acceptable.
 *  @retval **ERROR**           Other errors if, for example, the key is not found
 *  @warning The callee is responsible for iterating through passwords
 *           to ensure signing/encryption can occur successfully. 
 *  
 */
typedef PEP_STATUS (*ensure_passphrase_t)(PEP_SESSION session, const char* fpr);

/**
 *  <!--       init()       -->
 *  
 *  @brief Initialize pEpEngine for a thread
 *  
 *  @param[out]    session              init() allocates session memory and
 *                                      returns a pointer as a handle
 *  @param[in]   messageToSend        callback for sending message by the
 *                                      application
 *  @param[in]   inject_sync_event    callback for injecting a sync event
 *  @param[in]   ensure_passphrase    callback for ensuring correct password for key is set
 *  
 *  @retval PEP_STATUS_OK                       if init() succeeds
 *  @retval PEP_INIT_SQLITE3_WITHOUT_MUTEX      if SQLite3 was compiled with
 *                                              SQLITE_THREADSAFE 0
 *  @retval PEP_INIT_CANNOT_LOAD_CRYPTO_LIB     if crypto lin cannot be found
 *  @retval PEP_INIT_CRYPTO_LIB_INIT_FAILED     if CRYPTO_LIB init fails
 *  @retval PEP_INIT_CANNOT_OPEN_DB             if user's management db cannot be
 *                                              opened
 *  @retval PEP_INIT_CANNOT_OPEN_SYSTEM_DB      if system's management db cannot be
 *                                              opened
 *  
 *  @warning THE CALLER MUST GUARD THIS CALL EXTERNALLY WITH A MUTEX. release()
 *           should be similarly guarded.
 * 
 *  @warning the pointer is valid only if the return value is PEP_STATUS_OK
 *           in other case a NULL pointer will be returned; a valid handle must
 *           be released using release() when it's no longer needed
 * 
 *  @warning the caller has to guarantee that the first call to this function
 *           will succeed before further calls can be done
 *           messageToSend can only be null if no transport is application based
 *           if transport system is not used it must not be NULL
 * 
 *  @warning ensure_refresh_key should only be NULL if the 
 *           caller can guarantee that there is only one single or zero passphrases 
 *           used in the whole of the keys database
 *  
 */

DYNAMIC_API PEP_STATUS init(
        PEP_SESSION *session,
        messageToSend_t messageToSend,
        inject_sync_event_t inject_sync_event,
        ensure_passphrase_t ensure_passphrase
    );



/**
 *  <!--       release()       -->
 *  
 *  @brief Release thread session handle
 *  
 *  @param[in]   session    session handle to release
 *  
 *  @warning THE CALLER MUST GUARD THIS CALL EXTERNALLY WITH A MUTEX. init() should
 *           be similarly guarded.
 * 
 *  @warning the last release() can be called only when all other release() calls
 *           are done
 *  
 */

DYNAMIC_API void release(PEP_SESSION session);

/**
 *  <!--       config_passive_mode()       -->
 *  
 *  @brief Enable passive mode
 *  
 *  @param[in]   session    session handle
 *  @param[in]   enable     flag if enabled or disabled
 *  
 *  
 */

DYNAMIC_API void config_passive_mode(PEP_SESSION session, bool enable);


/**
 *  <!--       config_unencrypted_subject()       -->
 *  
 *  @brief Disable subject encryption
 *  
 *  @param[in]   session    session handle
 *  @param[in]   enable     flag if enabled or disabled
 *  
 *  
 */

DYNAMIC_API void config_unencrypted_subject(PEP_SESSION session, bool enable);


/**
 *  <!--       config_use_only_own_private_keys()       -->
 *  
 *  @brief Enable passive mode
 *  
 *  @param[in]   session    session handle
 *  @param[in]   enable     flag if enabled or disabled
 *  
 *  
 */

DYNAMIC_API void config_use_only_own_private_keys(PEP_SESSION session, bool enable);


/**
 *  <!--       config_service_log()       -->
 *  
 *  @brief Log more for service purposes
 *  
 *  @param[in]  session     session handle
 *  @param[in]  enable      flag if enabled or disabled
 *  
 *  
 */

DYNAMIC_API void config_service_log(PEP_SESSION session, bool enable);


/**
 *  @enum    PEP_CIPHER_SUITE
 *  
 *  @brief    TODO
 *  
 */
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

/**
 *  <!--       config_cipher_suite()       -->
 *  
 *  @brief Cipher suite being used when encrypting
 *  
 *  @param[in]   session         session handle
 *  @param[in]   cipher_suite    cipher suite to use
 *  
 *  @retval PEP_STATUS_OK           cipher suite configured
 *  @retval PEP_CANNOT_CONFIG       configuration failed; falling back to default
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter values
 *  
 *  @warning the default ciphersuite for a crypt tech implementation is implementation defined
 *  
 */

DYNAMIC_API PEP_STATUS config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);


/**
 *  @enum    PEP_HONOR_EXTRA_KEYS
*/

typedef enum _PEP_HONOR_EXTRA_KEYS {
    PEP_honor_incoming = 0,
    PEP_honor_incoming_and_outgoing = 1,
    PEP_honor_none = 2
} PEP_HONOR_EXTRA_KEYS;


/**
 *  <!--       config_honor_extra_keys()       -->
 *  
 *  @brief      Honor extra keys in incoming messages, in both directions or
 *              none of them
 *
 *  @param[in]   session            session handle
 *  @param[in]   honor_extra_keys
 *
 *  @warning pEp engine's standard is to accept that comm partners are using BCC
 *           and extra keys. If switched off by delivering PEP_honor_none no
 *           green rating can be achieved anymore if the usage of BCC or extra
 *           keys is detected
 *           incoming and outgoing means that pEp engine uses extra keys in
 *           replies on request of the communication partner
 *           pEp applications may set PEP_honor_incoming_and_outgoing by
 *           default but are required to clearly mark this to the user
 */

DYNAMIC_API PEP_STATUS config_honor_extra_keys(PEP_SESSION session,
        PEP_HONOR_EXTRA_KEYS honor_extra_keys);


/**
 *  <!--       decrypt_and_verify()       -->
 *  
 *  @brief Decrypt and/or verify a message
 *  
 *  @param[in]     session         session handle
 *  @param[in]     ctext           cipher text to decrypt and/or verify
 *  @param[in]     csize           size of cipher text
 *  @param[in]     dsigtext        if extant, *detached* signature text for this
 *                                 message (or NULL if not)
 *  @param[in]     dsize           size of *detached* signature text for this
 *                                 message (0, if no detached sig exists)
 *  @param[out]    ptext           pointer to internal buffer with plain text
 *  @param[out]    psize           size of plain text
 *  @param[out]    keylist         list of key ids which where used to encrypt
 *  @param[out]    filename_ptr    mails produced by certain PGP implementations 
 *                                 may return a decrypted filename here for attachments. 
 *                                 Externally, this can generally be NULL, and is an optional
 *                                 parameter.
 *  
 *  @retval PEP_UNENCRYPTED               message was unencrypted and not signed
 *  @retval PEP_VERIFIED                  message was unencrypted, signature matches
 *  @retval PEP_DECRYPTED                 message is decrypted now, no signature
 *  @retval PEP_DECRYPTED_AND_VERIFIED    message is decrypted now and verified
 *  @retval PEP_DECRYPT_WRONG_FORMAT      message has wrong format to handle
 *  @retval PEP_DECRYPT_NO_KEY            key not available to decrypt and/or verify
 *  @retval PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH    wrong signature
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter values
 *
 *  @warning the ownerships of ptext as well as keylist are going to the caller
 *           the caller must use free() (or an Windoze pEp_free()) and
 *           free_stringlist() to free them
 * 
 *  @note if this function fails an error message may be the first element of
 *        keylist and the other elements may be the keys used for encryption
 *  
 */

DYNAMIC_API PEP_STATUS decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char ** filename_ptr
    );


/**
 *  <!--       verify_text()       -->
 *  
 *  @brief Verfy plain text with a digital signature
 *  
 *  @param[in]     session      session handle
 *  @param[in]     text         text to verify
 *  @param[in]     size         size of text
 *  @param[in]     signature    signature text
 *  @param[in]     sig_size     size of signature
 *  @param[out]    keylist      list of key ids which where used to encrypt or NULL on
 *                              error
 *  
 *  @retval PEP_VERIFIED                message was unencrypted, signature matches
 *  @retval PEP_DECRYPT_NO_KEY          key not available to decrypt and/or verify
 *  @retval PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH    wrong signature
 *  @retval PEP_ILLEGAL_VALUE           illegal parameter values
 *  
 */

DYNAMIC_API PEP_STATUS verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );


/**
 *  <!--       encrypt_and_sign()       -->
 *  
 *  @brief Encrypt and sign a message
 *  
 *  @param[in]     session    session handle
 *  @param[in]     keylist    list of key ids to encrypt with as C strings
 *  @param[in]     ptext      plain text to decrypt and/or verify
 *  @param[in]     psize      size of plain text
 *  @param[out]    ctext      pointer to internal buffer with cipher text
 *  @param[out]    csize      size of cipher text
 *  
 *  @retval PEP_STATUS_OK                encryption and signing succeeded
 *  @retval PEP_KEY_NOT_FOUND            at least one of the recipient keys
 *                                           could not be found
 *  @retval PEP_KEY_HAS_AMBIG_NAME       at least one of the recipient keys has
 *                                           an ambiguous name
 *  @retval PEP_GET_KEY_FAILED           cannot retrieve key
 *  @retval PEP_ILLEGAL_VALUE           illegal parameter values
 *  
 *  @warning the ownership of ctext goes to the caller
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *           the first key in keylist is being used to sign the message
 *           this implies there has to be a private key for that keypair
 *  
 */

DYNAMIC_API PEP_STATUS encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

/**
 *  <!--       probe_encrypt()       -->
 *
 *  @brief Test if passphrase for a key is working in current session
 *
 *  @param[in]   session    session handle
 *  @param[in]   fpr        fingerprint of key to test
 *
 *  @retval PEP_STATUS_OK           in case passphrase works
 *  @retval error                   if not
 *
 *
 */

DYNAMIC_API PEP_STATUS probe_encrypt(PEP_SESSION session, const char *fpr);

/**
 *  <!--       set_debug_color()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle
 *  @param[in]  ansi_color     int
 *  
 */
DYNAMIC_API void set_debug_color(PEP_SESSION session, int ansi_color);

/**
 *  <!--       log_event()       -->
 *  
 *  @brief Log a user defined event defined by UTF-8 encoded strings into
 *         management log
 *  
 *  @param[in]   session        session handle
 *  @param[in]   title          C string with event name
 *  @param[in]   entity         C string with name of entity which is logging
 *  @param[in]   description    C string with long description for event or NULL if
 *                                  omitted
 *  @param[in]   comment        C string with user defined comment or NULL if
 *                                  omitted
 *  
 *  @retval PEP_STATUS_OK       log entry created
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter value  
 *  
 */

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session,
        const char *title,
        const char *entity,
        const char *description,
        const char *comment
    );


/**
 *  <!--       log_service()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle
 *  @param[in]  title          const char*
 *  @param[in]  entity         const char*
 *  @param[in]  description    const char*
 *  @param[in]  comment        const char*

 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE
 *  
 */
DYNAMIC_API PEP_STATUS log_service(PEP_SESSION session, const char *title,
        const char *entity, const char *description, const char *comment);

#define _STR_(x) #x
#define _D_STR_(x) _STR_(x)
#define S_LINE _D_STR_(__LINE__)

#define SERVICE_LOG(session, title, entity, desc) \
    log_service((session), (title), (entity), (desc), "service " __FILE__ ":" S_LINE)

/**
 *  <!--       _service_error_log()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session       session handle
 *  @param[in]  entity        const char*
 *  @param[in]  status        PEP_STATUS
 *  @param[in]  where         const char*
 *  
 */
DYNAMIC_API void _service_error_log(PEP_SESSION session, const char *entity,
        PEP_STATUS status, const char *where);

#define SERVICE_ERROR_LOG(session, entity, status) \
    _service_error_log((session), (entity), (status), __FILE__ ":" S_LINE)

/**
 *  <!--       trustword()       -->
 *  
 *  @brief Get the corresponding trustword for a 16 bit value
 *  
 *  @param[in]     session    session handle
 *  @param[in]     value      value to find a trustword for
 *  @param[in]     lang       C string with ISO 639-1 language code
 *  @param[out]    word       pointer to C string with trustword UTF-8 encoded;
 *                            NULL if language is not supported or trustword
 *                            wordlist is damaged or unavailable
 *  @param[out]    wsize      length of trustword
 *  
 *  @retval PEP_STATUS_OK            trustword retrieved
 *  @retval PEP_TRUSTWORD_NOT_FOUND  trustword not found
 *  @retval PEP_OUT_OF_MEMORY        out of memory 
 *  @retval PEP_ILLEGAL_VALUE        illegal parameter values
 *  
 *  @warning the word pointer goes to the ownership of the caller
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *  
 */

DYNAMIC_API PEP_STATUS trustword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        );


/**
 *  <!--       trustwords()       -->
 *  
 *  @brief Get trustwords for a string of hex values of a fingerprint
 *  
 *  @param[in]     session        session handle
 *  @param[in]     fingerprint    C string with hex values to find trustwords for
 *  @param[in]     lang           C string with ISO 639-1 language code
 *  @param[out]    words          pointer to C string with trustwords UTF-8 encoded,
 *                                separated by a blank each;
 *                                NULL if language is not supported or trustword
 *                                wordlist is damaged or unavailable
 *  @param[out]    wsize          length of trustwords string
 *  @param[in]     max_words      only generate a string with max_words;
 *                                if max_words == 0 there is no such limit
 *  
 *  @retval PEP_STATUS_OK            trustwords retrieved
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
 *  @retval PEP_ILLEGAL_VALUE        illegal parameter values
 *  
 *  @warning the word pointer goes to the ownership of the caller
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 * 
 *  @warning DON'T USE THIS FUNCTION FROM HIGH LEVEL LANGUAGES!
 *           Better implement a simple one in the adapter yourself using trustword(), and
 *           return a list of trustwords.
 * 
 *  @warning This function is provided for being used by C and C++ programs only.
 *  
 */

DYNAMIC_API PEP_STATUS trustwords(
        PEP_SESSION session, const char *fingerprint, const char *lang,
        char **words, size_t *wsize, int max_words
    );


// TODO: increase versions in pEp.asn1 if rating changes

/**
 *  @enum    PEP_comm_type
 *  
 *  @brief    TODO
 *  
 */
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

/**
 *  @enum    identity_flags
 *  
 *  @brief    TODO
 *  
 */
typedef enum _identity_flags {
    // the first octet flags are app defined settings
    PEP_idf_not_for_sync = 0x0001,   // don't use this identity for sync
    PEP_idf_list = 0x0002,           // identity of list of persons
    // the second octet flags are calculated
    PEP_idf_devicegroup = 0x0100,     // identity of a device group member
    PEP_idf_org_ident = 0x0200,       // identity is associated with an org (i.e. NOT a private account - could be company email)
    PEP_idf_group_ident = 0x0400      // identity is a group identity (e.g. mailing list) - N.B. not related to device group!
} identity_flags;

typedef unsigned int identity_flags_t;

//typedef enum _keypair_flags {
//} keypair_flags;
//
//typedef unsigned int keypair_flags_t;

/**
 *  @struct    pEp_identity
 *  
 *  @brief    This is the engine representation of the pEp identity concept,
 *            which is at its base a user bound to an address (and is uniquely
 *            identified as such). Other information such as default keys,
 *            the default language used with the user, etc, are associated
 *            in this structure as well.
 *  
 */
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

/**
 *  @struct    identity_list
 *  
 *  @brief     List nodes for pEp_identity structs
 *  
 */
typedef struct _identity_list {
    pEp_identity *ident;            // This node's identity
    struct _identity_list *next;    // The next identity node in the list, or NULL if this is the tail
} identity_list;


/**
 *  <!--       new_identity()       -->
 *  
 *  @brief Allocate memory and set the string and size fields
 *  
 *  @param[in]   address     UTF-8 string or NULL
 *  @param[in]   fpr         UTF-8 string or NULL
 *  @param[in]   user_id     UTF-8 string or NULL
 *  @param[in]   username    UTF-8 string or NULL
 *  
 *  @retval pEp_identity    duplicate identity struct
 *  @retval NULL            if out of memory
 *  
 *  @ownership the strings are copied; the original strings are still being owned by
 *             the caller
 *  
 */

DYNAMIC_API pEp_identity *new_identity(
        const char *address, const char *fpr, const char *user_id,
        const char *username
    );


/**
 *  <!--       identity_dup()       -->
 *  
 *  @brief Allocate memory and duplicate
 *  
 *  @param[in]   src    identity to duplicate
 *  
 *  @retval pEp_identity    duplicate identity struct
 *  @retval NULL            if out of memory
 *  
 *  @ownership the strings are copied; the original strings are still being owned by
 *             the caller
 *  
 */

DYNAMIC_API pEp_identity *identity_dup(const pEp_identity *src);


/**
 *  <!--       free_identity()       -->
 *  
 *  @brief Free all memory being occupied by a pEp_identity struct
 *  
 *  @param[in]   identity    struct to release
 *  
 *  @warning not only the struct but also all string memory referenced by the
 *           struct is being freed; all pointers inside are invalid afterwards
 *  
 */

DYNAMIC_API void free_identity(pEp_identity *identity);


/**
 *  <!--       get_identity()       -->
 *  
 *  @brief Get identity information
 *  
 *  @param[in]     session     session handle
 *  @param[in]     address     C string with communication address, UTF-8 encoded
 *  @param[in]     user_id     unique C string to identify person that identity
 *                             is refering to
 *  @param[out]    identity    pointer to pEp_identity structure with results or
 *                             NULL if failure
 *  
 *  @retval        PEP_STATUS_OK
 *  @retval        PEP_ILLEGAL_VALUE        illegal parameter
 *  @retval        PEP_OUT_OF_MEMORY        out of memory 
 *  @retval        PEP_CANNOT_FIND_IDENTITY
 *
 *  @warning address and user_id are being copied; the original strings remains in
 *           the ownership of the caller
 *           the resulting pEp_identity structure goes to the ownership of the
 *           caller and has to be freed with free_identity() when not in use any
 *           more
 *  
 */

DYNAMIC_API PEP_STATUS get_identity(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    );


/**
 *  <!--       set_identity()       -->
 *  
 *  @brief Set identity information
 *  
 *  @param[in]   session     session handle
 *  @param[in]   identity    pointer to pEp_identity structure
 *  
 *  @retval PEP_STATUS_OK                 encryption and signing succeeded
 *  @retval PEP_CANNOT_SET_PERSON         writing to table person failed
 *  @retval PEP_CANNOT_SET_PGP_KEYPAIR    writing to table pgp_keypair failed
 *  @retval PEP_CANNOT_SET_IDENTITY       writing to table identity failed
 *  @retval PEP_COMMIT_FAILED             SQL commit failed
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter value
 *  @retval PEP_OUT_OF_MEMORY             out of memory
 *  
 *  @warning address, fpr, user_id and username must be given
 *  
 */

DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    );

/**
 *  <!--       get_default_own_userid()       -->
 *  
 *  @brief Get the user_id of the own user
 *  
 *  @param[in]     session    session handle
 *  @param[out]    userid     own user id (if it exists)
 *  
 *  @retval PEP_STATUS_OK                 userid was found
 *  @retval PEP_CANNOT_FIND_IDENTITY      no own_user found in the DB
 *  @retval PEP_UNKNOWN_ERROR             results were returned, but no ID
 *                                        found (no reason this should ever 
 *                                        occur)
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter value
 *  @retval PEP_OUT_OF_MEMORY             out of memory
 *  
 *  @warning userid will be NULL if not found; otherwise, returned string
 *           belongs to the caller.
 *  
 */

DYNAMIC_API PEP_STATUS get_default_own_userid(
        PEP_SESSION session, 
        char** userid
    );

/**
 *  <!--       get_userid_alias_default()       -->
 *  
 *  @brief Get the default user_id which corresponds
 *         to an alias
 *  
 *  @param[in]     session       session handle
 *  @param[in]     alias_id      the user_id which may be an alias for a default id
 *  @param[out]    default_id    the default id for this alias, if the alias
 *                               is in the DB as an alias, else NULL
 *  
 *  @retval PEP_STATUS_OK                 userid was found
 *  @retval PEP_CANNOT_FIND_ALIAS         this userid is not listed as an 
 *                                        alias in the DB
 *  @retval PEP_UNKNOWN_ERROR             results were returned, but no ID
 *                                        found (no reason this should ever 
 *                                        occur)
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter value
 *  @retval PEP_OUT_OF_MEMORY             out of memory
 *  
 *  @warning default_id will be NULL if not found; otherwise, returned string
 *           belongs to the caller.
 *           also, current implementation does NOT check to see if this userid
 *           IS a default.
 *  
 */

DYNAMIC_API PEP_STATUS get_userid_alias_default(
        PEP_SESSION session, 
        const char* alias_id,
        char** default_id);

/**
 *  <!--       set_userid_alias()       -->
 *  
 *  @brief Set an alias to correspond to a default id
 *  
 *  @param[in]   session       session handle
 *  @param[in]   default_id    the default id for this alias. This must
 *                               correspond to the default user_id for an
 *                               entry in the person (user) table.
 *  @param[in]   alias_id      the alias to be set for this default id
 *  
 *  @retval PEP_STATUS_OK                 userid was found
 *  @retval PEP_CANNOT_SET_ALIAS          there was an error setting this
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter value
 *  
 *  
 */

DYNAMIC_API PEP_STATUS set_userid_alias (
        PEP_SESSION session, 
        const char* default_id,
        const char* alias_id);

/**
 *  <!--       set_identity_flags()       -->
 *  
 *  @brief Update identity flags on existing identity
 *  
 *  @param[in]      session    session handle
 *  @param[in,out]  identity   pointer to pEp_identity structure
 *  @param[in]      flags      new value for flags
 *  
 *  @retval PEP_STATUS_OK                 encryption and signing succeeded
 *  @retval PEP_CANNOT_SET_IDENTITY       update of identity failed
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter value
 *  
 *  @warning address and user_id must be given in identity
 *  
 */

DYNAMIC_API PEP_STATUS set_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        identity_flags_t flags
    );

/**
 *  <!--       unset_identity_flags()       -->
 *  
 *  @brief Update identity flags on existing identity
 *  
 *  @param[in]      session    session handle
 *  @param[in,out]  identity   pointer to pEp_identity structure
 *  @param[in]      flags      new value for flags
 *  
 *  @retval PEP_STATUS_OK                 encryption and signing succeeded
 *  @retval PEP_CANNOT_SET_IDENTITY       update of identity failed
 *  @retval PEP_ILLEGAL_VALUE             illegal parameter value
 *  
 *  @warning address and user_id must be given in identity
 *  
 */

DYNAMIC_API PEP_STATUS unset_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        identity_flags_t flags
    );

/**
 *  <!--       mark_as_compromised()       -->
 *  
 *  @brief Mark key in trust db as compromised
 *  
 *  @param[in]   session    session handle
 *  @param[in]   fpr        fingerprint of key to mark
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE 
 *  @retval PEP_CANNOT_SET_TRUST
 *
 */
DYNAMIC_API PEP_STATUS mark_as_compromised(
        PEP_SESSION session,
        const char *fpr
    );

/**
 *  <!--       mark_as_compromized()       -->
 *  
 *  @brief Deprecated to fix misspelling. Please move to
 *         mark_as_compromised();
 *  
 *  
 */

DYNAMIC_API PEP_STATUS mark_as_compromized(
        PEP_SESSION session,
        const char *fpr
    );


/**
 *  <!--       generate_keypair()       -->
 *  
 *  @brief Generate a new key pair and add it to the key ring
 *  
 *  @param[in]     session     session handle
 *  @param[in,out] identity    pointer to pEp_identity structure
 *  
 *  @retval PEP_STATUS_OK           encryption and signing succeeded
 *  @retval PEP_ILLEGAL_VALUE       illegal values for identity fields given
 *  @retval PEP_CANNOT_CREATE_KEY   key engine is on strike
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 *  
 *  @warning address must be set to UTF-8 string
 *           the fpr field must be set to NULL
 *           username field must either be NULL or be a UTF8-string conforming 
 *           to RFC4880 for PGP uid usernames  
 * 
 *  @note this function allocates a string and sets set fpr field of identity
 *        the caller is responsible to call free() for that string or use
 *        free_identity() on the struct
 *  
 */

DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    );


/**
 *  <!--       delete_keypair()       -->
 *  
 *  @brief Delete a public key or a key pair from the key ring
 *  
 *  @param[in]   session    session handle
 *  @param[in]   fpr        C string with fingerprint of the
 *                            public key
 *  
 *  @retval PEP_STATUS_OK           key was successfully deleted
 *  @retval PEP_KEY_NOT_FOUND       key not found
 *  @retval PEP_ILLEGAL_VALUE       not a valid fingerprint
 *  @retval PEP_KEY_HAS_AMBIG_NAME  fpr does not uniquely identify a key
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  
 *  
 */

DYNAMIC_API PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr);


/**
 *  <!--       import_key()       -->
 *  
 *  @brief Import key from data
 *  
 *  @param[in]     session         session handle
 *  @param[in]     key_data        key data, i.e. ASCII armored OpenPGP key
 *  @param[in]     size            amount of data to handle
 *  @param[out]    private_keys    list of identities containing the 
 *                                 private keys that have been imported
 *  
 *  @retval PEP_KEY_IMPORTED        key was successfully imported
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval PEP_ILLEGAL_VALUE       there is no key data to import
 *  
 *  @warning private_keys goes to the ownership of the caller
 *           private_keys can be left NULL, it is then ignored
 *  
 */

DYNAMIC_API PEP_STATUS import_key(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_keys       
    );


/**
 *  <!--       export_key()       -->
 *  
 *  @brief Export ascii armored key
 *  
 *  @param[in]     session     session handle
 *  @param[in]     fpr         fingerprint of key
 *  @param[out]    key_data    ASCII armored OpenPGP key
 *  @param[out]    size        amount of data to handle
 *  
 *  @retval PEP_STATUS_OK           key was successfully exported
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval PEP_KEY_NOT_FOUND       key not found
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter value
 *  
 *  @warning the key_data goes to the ownership of the caller
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *  
 */

DYNAMIC_API PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );


/**
 *  <!--       export_secret_key()       -->
 *  
 *  @brief Export secret key ascii armored
 *  
 *  @param[in]     session     session handle
 *  @param[in]     fpr         fingerprint of key, at least 16 hex digits
 *  @param[out]    key_data    ASCII armored OpenPGP secret key
 *  @param[out]    size        amount of data to handle
 *  
 *  @retval PEP_STATUS_OK           key was successfully exported
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval PEP_KEY_NOT_FOUND       key not found
 *  @retval PEP_CANNOT_EXPORT_KEY   cannot export secret key (i.e. it's on an HKS)
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter value
 *  
 *  @warning the key_data goes to the ownership of the caller
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *           beware of leaking secret key data - overwrite it in memory after use
 *  
 */

DYNAMIC_API PEP_STATUS export_secret_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );


/**
 *  <!--       export_secrect_key()       -->
 *  
 *  @brief Deprecated misspelled function. Please replace with
 *         export_secret_key
 *  
 *  @deprecated
 */

DYNAMIC_API PEP_STATUS export_secrect_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    );


/**
 *  <!--       recv_key()       -->
 *  
 *  @brief Update key(s) from keyserver
 *  
 *  @param[in]   session    session handle
 *  @param[in]   pattern    key id, user id or address to search for as
 *                            UTF-8 string
 *  
 *  
 */

DYNAMIC_API PEP_STATUS recv_key(PEP_SESSION session, const char *pattern);


/**
 *  <!--       find_keys()       -->
 *  
 *  @brief Find keys in keyring
 *  
 *  @param[in]     session    session handle
 *  @param[in]     pattern    fingerprint or address to search for as
 *                            UTF-8 string
 *  @param[out]    keylist    list of fingerprints found or NULL on error
 *  
 *  @retval        PEP_STATUS_OK        
 *  @retval        PEP_ILLEGAL_VALUE    illegal parametres
 *
 *  @warning the ownership of keylist and its elements go to the caller
 *           the caller must use free_stringlist() to free it
 *  
 */


DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

/**
 *  <!--       send_key()       -->
 *  
 *  @brief Send key(s) to keyserver
 *  
 *  @param[in]     session    session handle
 *  @param[in]     pattern    key id, user id or address to search for as
 *                            UTF-8 string
 *  
 *  
 */

DYNAMIC_API PEP_STATUS send_key(PEP_SESSION session, const char *pattern);


/**
 *  <!--       pEp_free()       -->
 *  
 *  @brief Free memory allocated by pEp engine
 *  
 *  @param[in]     p    pointer to free <br>
 *                      The reason for this function is that heap management can be a pretty
 *                      complex task with Windoze. This free() version calls the free()
 *                      implementation of the C runtime library which was used to build pEp engine,
 *                      so you're using the correct heap. For more information, see:
 *                      <http://msdn.microsoft.com/en-us/library/windows/desktop/aa366711(v=vs.85).aspx>
 *  
 *  
 */

DYNAMIC_API void pEp_free(void *p);


/**
 *  <!--       pEp_realloc()       -->
 *  
 *  @brief Reallocate memory allocated by pEp engine
 *  
 *  @param[in]   p       pointer to free
 *  @param[in]   size    new memory size
 *  
 *  @retval pointer to allocated memory
 * 
 *  @note The reason for this function is that heap management can be a pretty
 *        complex task with Windoze. This realloc() version calls the realloc()
 *        implementation of the C runtime library which was used to build pEp engine,
 *        so you're using the correct heap. For more information, see:
 *        <http://msdn.microsoft.com/en-us/library/windows/desktop/aa366711(v=vs.85).aspx>
 *  
 *  
 */

DYNAMIC_API void *pEp_realloc(void *p, size_t size);


/**
 *  <!--       get_trust()       -->
 *  
 *  @brief Get the trust level a key has for a person
 *  
 *  @param[in]     session     session handle
 *  @param[in,out] identity    user_id and fpr to check as UTF-8 strings (in)
 *                             comm_type as result (out)
 *                             this function modifies the given identity struct; the struct remains in
 *                             the ownership of the caller
 *                             if the trust level cannot be determined identity->comm_type is set
 *                             to PEP_ct_unknown
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE         illegal parameter value
 *  @retval        PEP_CANNOT_FIND_IDENTITY  
 *
 */

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity);


/**
 *  <!--       least_trust()       -->
 *  
 *  @brief Get the least known trust level for a key in the database
 *  
 *  @param[in]     session      session handle
 *  @param[in]     fpr          fingerprint of key to check
 *  @param[out]    comm_type    least comm_type as result (out)
 *                              if the trust level cannot be determined comm_type is set to PEP_ct_unknown
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_CANNOT_FIND_IDENTITY    
 *  
 */

DYNAMIC_API PEP_STATUS least_trust(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );


/**
 *  <!--       get_key_rating()       -->
 *  
 *  @brief Get the rating a bare key has
 *  
 *  @param[in]     session      session handle
 *  @param[in]     fpr          unique identifyer for key as UTF-8 string
 *  @param[out]    comm_type    key rating
 *                              if an error occurs, *comm_type is set to PEP_ct_unknown and an error
 *                              is returned
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  
 */

DYNAMIC_API PEP_STATUS get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );


/**
 *  <!--       renew_key()       -->
 *  
 *  @brief Renew an expired key
 *  
 *  @param[in]   session    session handle
 *  @param[in]   fpr        ID of key to renew as UTF-8 string
 *  @param[in]   ts         timestamp when key should expire or NULL for
 *                            default
 *  
 *  @retval        PEP_STATUS_OK        key renewed       
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_KEY_NOT_FOUND    key not found
 *  
 */

DYNAMIC_API PEP_STATUS renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    );


/**
 *  <!--       revoke_key()       -->
 *  
 *  @brief Revoke a key
 *  
 *  @param[in]   session    session handle
 *  @param[in]   fpr        ID of key to revoke as UTF-8 string
 *  @param[in]   reason     text with reason for revoke as UTF-8 string
 *                            or NULL if reason unknown
 *
 *  @retval        PEP_STATUS_OK        if key revoked      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_KEY_NOT_FOUND    key not found
 *  
 *  @warning reason text must not include empty lines
 *           this function is meant for internal use only; better use
 *           key_mistrusted() of keymanagement API
 *  
 */

DYNAMIC_API PEP_STATUS revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    );


/**
 *  <!--       key_expired()       -->
 *  
 *  @brief Flags if a key is already expired
 *  
 *  @param[in]     session    session handle
 *  @param[in]     fpr        ID of key to check as UTF-8 string
 *  @param[in]     when       UTC time of when should expiry be considered
 *  @param[out]    expired    flag if key expired
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_KEY_NOT_FOUND    key not found
 *  
 */

DYNAMIC_API PEP_STATUS key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    );

    
/**
 *  <!--       key_revoked()       -->
 *  
 *  @brief Flags if a key is already revoked
 *  
 *  @param[in]     session    session handle
 *  @param[in]     fpr        ID of key to check as UTF-8 string
 *  @param[out]    revoked    flag if key revoked
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_KEY_NOT_FOUND    key not found
 *  
 */

DYNAMIC_API PEP_STATUS key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    );


/**
 *  <!--       get_crashdump_log()       -->
 *  
 *  @brief Get the last log messages out
 *  
 *  @param[in]     session     session handle
 *  @param[in]     maxlines    maximum number of lines (0 for default)
 *  @param[out]    logdata     logdata as string in double quoted CSV format
 *                             column1 is title
 *                             column2 is entity
 *                             column3 is description
 *                             column4 is comment
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval PEP_UNKNOWN_ERROR   
 * 
 *  @warning the ownership of logdata goes to the caller
 *  
 */

DYNAMIC_API PEP_STATUS get_crashdump_log(
        PEP_SESSION session,
        int maxlines,
        char **logdata
    );


/**
 *  <!--       get_languagelist()       -->
 *  
 *  @brief Get the list of languages
 *  
 *  @param[in]     session      session handle
 *  @param[out]    languages    languages as string in double quoted CSV format
 *                              column 1 is the ISO 639-1 language code
 *                              column 2 is the name of the language
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval PEP_UNKNOWN_DB_ERROR
 *  
 *  @warning the ownership of languages goes to the caller
 *  
 */

DYNAMIC_API PEP_STATUS get_languagelist(
        PEP_SESSION session,
        char **languages
    );


/**
 *  <!--       get_phrase()       -->
 *  
 *  @brief Get phrase in a dedicated language through i18n
 *  
 *  @param[in]     session      session handle
 *  @param[in]     lang         C string with ISO 639-1 language code
 *  @param[in]     phrase_id    id of phrase in i18n
 *  @param[out]    phrase       phrase as UTF-8 string
 *  
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY       out of memory
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *  @retval     PEP_PHRASE_NOT_FOUND
 *
 *  @warning the ownership of phrase goes to the caller
 *  
 */

DYNAMIC_API PEP_STATUS get_phrase(
        PEP_SESSION session,
        const char *lang,
        int phrase_id,
        char **phrase
    );


/**
 *  <!--       sequence_value()       -->
 *  
 *  @brief Raise the value of a named sequence and retrieve it
 *  
 *  @param[in]     session    session handle
 *  @param[in]     name       name of sequence
 *  @param[out]    value      value of sequence
 *  
 *  @retval PEP_STATUS_OK                   no error, not own sequence
 *  @retval PEP_SEQUENCE_VIOLATED           if sequence violated
 *  @retval PEP_CANNOT_INCREASE_SEQUENCE    if sequence cannot be increased
 *  @retval PEP_OWN_SEQUENCE                if own sequence
 *  @retval PEP_COMMIT_FAILED
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter value
 *  
 *  
 */

DYNAMIC_API PEP_STATUS sequence_value(
        PEP_SESSION session,
        const char *name,
        int32_t *value
    );


/**
 *  <!--       set_revoked()       -->
 *  
 *  @brief Records relation between a revoked key and its replacement
 *  
 *  @param[in]     session            session handle
 *  @param[in]     revoked_fpr        revoked fingerprint
 *  @param[in]     replacement_fpr    replacement key fingerprint
 *  @param[in]     revocation_date    revocation date
 *  
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *  
 */

DYNAMIC_API PEP_STATUS set_revoked(
       PEP_SESSION session,
       const char *revoked_fpr,
       const char *replacement_fpr,
       const uint64_t revocation_date
    );


/**
 *  <!--       get_revoked()       -->
 *  
 *  @brief Find revoked key that may have been replaced by given key, if any
 *  
 *  @param[in]     session            session handle
 *  @param[in]     fpr                given fingerprint
 *  @param[out]    revoked_fpr        revoked fingerprint
 *  @param[out]    revocation_date    revocation date
 *  
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY  
 *
 */
    
DYNAMIC_API PEP_STATUS get_revoked(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    );


/**
 *  <!--       get_engine_version()       -->
 *  
 *  @brief Returns the current version of pEpEngine (this is different
 *         from the pEp protocol version!)
 *  
 *  @retval  PEP_ENGINE_VERSION 
 *  
 */
DYNAMIC_API const char* get_engine_version();

/**
 *  <!--       get_protocol_version()       -->
 *  
 *  @brief Returns the pEp protocol version
 *  
 *  @retval     PEP_VERSION
 *  
 */

DYNAMIC_API const char *get_protocol_version();

/**
 *  <!--       is_pEp_user()       -->
 *  
 *  @brief Returns true if the USER corresponding to this identity 
 *         has been listed in the *person* table as a pEp user. 
 *  
 *  @param[in]     identity    identity containing the user_id to check (this is
 *                             the only part of the struct we require to be set)
 *  @param[out]    is_pEp      boolean pointer - will return true or false by
 *                             reference with respect to whether or not user is
 *                             a known pEp user
 *  
 *  @retval PEP_STATUS_OK           if user found in person table
 *  @retval PEP_ILLEGAL_VALUE       if no user_id in input
 *  @retval PEP_CANNOT_FIND_PERSON  if user_id doesn't exist
 *  
 *  
 */
DYNAMIC_API PEP_STATUS is_pEp_user(PEP_SESSION session, 
                                   pEp_identity *identity, 
                                   bool* is_pEp);

/**
 *  <!--       per_user_directory()       -->
 *  
 *  @brief Returns the directory for pEp management db
 *  
 *  @retval char*   path to actual per user directory
 *  @retval NULL    on failure
 *  
 *  
 */

DYNAMIC_API const char *per_user_directory(void);


/**
 *  <!--       per_machine_directory()       -->
 *  
 *  @brief Returns the directory for pEp system db
 *  
 *  @retval char*   path to actual per machine directory
 *  @retval NULL    on failure
 *  
 *  
 */

DYNAMIC_API const char *per_machine_directory(void);

// FIXME: replace in canonical style
//
/**
 *  <!--       config_passphrase()       -->
 *  
 *  @brief Configure a key passphrase for the current session.
 *  
 *  A passphrase can be configured into a p≡p session. Then it is used whenever a
 *  secret key is used which requires a passphrase.
 * 
 *  A passphrase is a string between 1 and 1024 bytes and is only ever present in
 *  memory. Because strings in the p≡p engine are UTF-8 NFC, the string is
 *  restricted to 250 code points in UI.
 * 
 *  This function copies the passphrase into the session. It may return
 *  PEP_OUT_OF_MEMORY. The behaviour of all functions which use secret keys may
 *  change after this is configured.  
 * 
 *  Error behaviour:
 * 
 *  For any function which may trigger the use of a secret key, if an attempt
 *  to use a secret key which requires a passphrase occurs and no passphrase
 *  is configured for the current session, PEP_PASSPHRASE_REQUIRED is
 *  returned by this function (and thus, all functions which could trigger
 *  such a usage must be prepared to return this value).  For any function
 *  which may trigger the use of a secret key, if a passphrase is configured
 *  and the configured passphrase is the wrong passphrase for the use of a
 *  given passphrase-protected secret key, PEP_WRONG_PASSPHRASE is returned
 *  by this function (and thus, all functions which could trigger such a
 *  usage must be prepared to return this value).
 *  
 *  
 *  @param[in]     session      session handle
 *  @param[in]     passphrase
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_OUT_OF_MEMORY    out of memory
 *
 */

DYNAMIC_API PEP_STATUS config_passphrase(PEP_SESSION session, const char *passphrase);

// FIXME: replace in canonical style
//

/**
 *  <!--       config_passphrase_for_new_keys()       -->
 * 
 * @brief Passphrase enablement for newly-generated secret keys
 * 
 * If it is desired that new p≡p keys are passphrase-protected, the following
 * API call is used to enable the addition of passphrases to new keys during key
 * generation.
 *
 * If enabled and a passphrase for new keys has been configured
 * through this function (NOT the one above - this is a separate passphrase!),
 * then anytime a secret key is generated while enabled, the configured
 * passphrase will be used as the passphrase for any newly-generated secret key.
 *
 * If enabled and a passphrase for new keys has not been configured, then any
 * function which can attempt to generate a secret key will return
 * PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED.  
 *
 * If disabled (i.e. not enabled) and a passphrase for new keys has been
 * configured, no passphrases will be used for newly-generated keys.
 *
 * This function copies the passphrase for new keys into a special field that is
 * specifically for key generation into the session. It may return
 * PEP_OUT_OF_MEMORY. The behaviour of all functions which use secret keys may
 * change after this is configured.
 *
 *  @param[in]     session      session handle
 *  @param[in]     enable     
 *  @param[in]     passphrase
 *  
 *  @retval        PEP_STATUS_OK      
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_OUT_OF_MEMORY    out of memory
 *  
 */

DYNAMIC_API PEP_STATUS config_passphrase_for_new_keys(PEP_SESSION session, 
                                                bool enable, 
                                                const char *passphrase);
/**
 *  <!--       set_ident_enc_format()       -->
 *  
 *  @brief Set the default encryption format for this identity
 *         (value only MIGHT be used, and only in the case where the
 *         message enc_format is PEP_enc_auto. It will be used 
 *         opportunistically in the case on a first-come, first-serve 
 *         basis in the order of to_list, cc_list, and bcc_list. We take 
 *         the first set value we come to)
 *  
 *  @param[in]   session     session handle
 *  @param[in]   identity    identity->user_id and identity->address must NOT be NULL
 *  @param[in]   format      the desired default encryption format
 *
 *  @retval     PEP_STATUS_OK      
 *  @retval     PEP_ILLEGAL_VALUE        illegal parameter value
 *  @retval     PEP_CANNOT_SET_IDENTITY  
 *  
 */

DYNAMIC_API PEP_STATUS set_ident_enc_format(PEP_SESSION session,
                                            pEp_identity *identity,
                                            PEP_enc_format format);

/**
 *  <!--       reset_pEptest_hack()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *
 *
 *  @retval       PEP_STATUS_OK      
 *  @retval       PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval       PEP_UNKNOWN_DB_ERROR
 *
 */
DYNAMIC_API PEP_STATUS reset_pEptest_hack(PEP_SESSION session);

    
/**
 *  <!--       get_replacement_fpr()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session          session handle
 *  @param[in]  fpr              const char*
 *  @param[in]  revoked_fpr      char**
 *  @param[in]  revocation_date  uint64_t*
 *  
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *
 */
DYNAMIC_API PEP_STATUS get_replacement_fpr(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    );
    

// This ONLY sets the *user* flag, and creates a shell identity if necessary.
/**
 *  <!--       set_as_pEp_user()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session      session handle
 *  @param[in]  user         pEp_identity*
 *  
 *  @retval     PEP_STATUS_OK      
 *  @retval     PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval     PEP_CANNOT_SET_PERSON  
 *
 */
DYNAMIC_API PEP_STATUS set_as_pEp_user(PEP_SESSION session, pEp_identity* user);


#ifdef __cplusplus
}
#endif
#endif
