#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "dynamic_api.h"
#include "stringlist.h"
#include "timestamp.h"

#define PEP_VERSION "1.0"

// pEp Engine API

//  caveat:
//      Unicode data has to be normalized to NFC before calling
//      UTF-8 strings are UTF-8 encoded C strings (zero terminated)


struct _pEpSession;
typedef struct _pEpSession * PEP_SESSION;

typedef enum {
	PEP_STATUS_OK									= 0,

	PEP_INIT_CANNOT_LOAD_GPGME						= 0x0110,
	PEP_INIT_GPGME_INIT_FAILED						= 0x0111,
	PEP_INIT_NO_GPG_HOME							= 0x0112,
	PEP_INIT_NETPGP_INIT_FAILED						= 0x0113,

	PEP_INIT_SQLITE3_WITHOUT_MUTEX					= 0x0120,
	PEP_INIT_CANNOT_OPEN_DB							= 0x0121,
	PEP_INIT_CANNOT_OPEN_SYSTEM_DB					= 0x0122,
	
	PEP_KEY_NOT_FOUND						        = 0x0201,
	PEP_KEY_HAS_AMBIG_NAME					        = 0x0202,
	PEP_GET_KEY_FAILED						        = 0x0203,
	
	PEP_CANNOT_FIND_IDENTITY						= 0x0301,
	PEP_CANNOT_SET_PERSON							= 0x0381,
	PEP_CANNOT_SET_PGP_KEYPAIR						= 0x0382,
	PEP_CANNOT_SET_IDENTITY							= 0x0383,
	
	PEP_UNENCRYPTED									= 0x0400,
	PEP_VERIFIED									= 0x0401,
	PEP_DECRYPTED									= 0x0402,
	PEP_DECRYPTED_AND_VERIFIED						= 0x0403,
	PEP_DECRYPT_WRONG_FORMAT						= 0x0404,
	PEP_DECRYPT_NO_KEY								= 0x0405,
	PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH			= 0x0406,
    PEP_VERIFY_NO_KEY                               = 0x0407,
    PEP_VERIFIED_AND_TRUSTED                        = 0x0408,
	PEP_CANNOT_DECRYPT_UNKNOWN						= 0x04ff,

	PEP_TRUSTWORD_NOT_FOUND							= 0x0501,

    PEP_CANNOT_CREATE_KEY                           = 0x0601,
    PEP_CANNOT_SEND_KEY                             = 0x0602,

	PEP_COMMIT_FAILED								= 0xff01,

    PEP_CANNOT_CREATE_TEMP_FILE                     = -5,
    PEP_ILLEGAL_VALUE                               = -4,
    PEP_BUFFER_TOO_SMALL                            = -3,
	PEP_OUT_OF_MEMORY								= -2,
	PEP_UNKNOWN_ERROR								= -1
} PEP_STATUS;


// INIT_STATUS init() - initialize pEpEngine for a thread
//
//  parameters:
//		session (out)	init() allocates session memory and returns a pointer
//		                as a handle
//
//  return value:
//		PEP_STATUS_OK = 0					if init() succeeds
//		PEP_INIT_SQLITE3_WITHOUT_MUTEX		if SQLite3 was compiled with
//		                                    SQLITE_THREADSAFE 0
//		PEP_INIT_CANNOT_LOAD_GPGME			if libgpgme.dll cannot be found
//		PEP_INIT_GPGME_INIT_FAILED			if GPGME init fails
//		PEP_INIT_CANNOT_OPEN_DB				if user's management db cannot be
//		                                    opened
//		PEP_INIT_CANNOT_OPEN_SYSTEM_DB		if system's management db cannot be
//		                                    opened
//
//  caveat:
//      the pointer is valid only if the return value is PEP_STATUS_OK
//      in other case a NULL pointer will be returned; a valid handle must
//      be released using release() when it's no longer needed
//
//      the caller has to guarantee that the first call to this function
//      will succeed before further calls can be done

DYNAMIC_API PEP_STATUS init(PEP_SESSION *session);


// void release() - release thread session handle
//
//  parameters:
//		session (in)	session handle to release
//
//	caveat:
//	    the last release() can be called only when all other release() calls
//	    are done

DYNAMIC_API void release(PEP_SESSION session);


// decrypt_and_verify() - decrypt and/or verify a message
//
//	parameters:
//		session (in)	session handle
//		ctext (in)		cipher text to decrypt and/or verify
//		csize (in)		size of cipher text
//		ptext (out)		pointer to internal buffer with plain text
//		psize (out)		size of plain text
//		keylist (out)	list of key ids which where used to encrypt
//
//	return value:
//		PEP_UNENCRYPTED				message was unencrypted and not signed
//		PEP_VERIFIED				message was unencrypted, signature matches
//		PEP_DECRYPTED				message is decrypted now, no signature
//		PEP_DECRYPTED_AND_VERIFIED	message is decrypted now and verified
//		PEP_DECRYPT_WRONG_FORMAT	message has wrong format to handle
//		PEP_DECRYPT_NO_KEY			key not available to decrypt and/or verify
//		PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH	wrong signature
//
//	caveat:
//	    the ownerships of ptext as well as keylist are going to the caller
//	    the caller must use free() (or an Windoze pEp_free()) and
//	    free_stringlist() to free them
//
//      if this function failes an error message may be the first element of
//      keylist and the other elements may be the keys used for encryption

DYNAMIC_API PEP_STATUS decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        char **ptext, size_t *psize, stringlist_t **keylist
    );


// verify_text() - verfy plain text with a digital signature
//
//  parameters:
//      session (in)    session handle
//      text (in)       text to verify
//      size (in)       size of text
//      signature (in)  signature text
//      sig_size (in)   size of signature
//		keylist (out)	list of key ids which where used to encrypt or NULL on
//		                error
//
//  return value:
//		PEP_VERIFIED				message was unencrypted, signature matches
//		PEP_DECRYPT_NO_KEY			key not available to decrypt and/or verify
//		PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH	wrong signature

DYNAMIC_API PEP_STATUS verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );


// encrypt_and_sign() - encrypt and sign a message
//
//	parameters:
//		session (in)	session handle
//		keylist (in)	list of key ids to encrypt with as C strings
//		ptext (in)		plain text to decrypt and/or verify
//		psize (in)		size of plain text
//		ctext (out)		pointer to internal buffer with cipher text
//		csize (out)		size of cipher text
//
//	return value:
//		PEP_STATUS_OK = 0				encryption and signing succeeded
//		PEP_KEY_NOT_FOUND	            at least one of the receipient keys
//		                                could not be found
//		PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
//		                                an ambiguous name
//		PEP_GET_KEY_FAILED		        cannot retrieve key
//
//	caveat:
//	    the ownership of ctext is going to the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())
//      the first key in keylist is being used to sign the message
//      this implies there has to be a private key for that keypair

DYNAMIC_API PEP_STATUS encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );


// log_event() - log a user defined event defined by UTF-8 encoded strings into
// management log
//
//	parameters:
//		session (in)		session handle
//		title (in)			C string with event name
//		entity (in)			C string with name of entity which is logging
//		description (in)	C string with long description for event or NULL if
//		                    omitted
//		comment (in)		C string with user defined comment or NULL if
//		                    omitted
//
//	return value:
//	    PEP_STATUS_OK       log entry created

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session, const char *title, const char *entity,
        const char *description, const char *comment
    );


// trustword() - get the corresponding trustword for a 16 bit value
//
//	parameters:
//		session (in)		    session handle
//		value (in)			    value to find a trustword for
//		lang (in)			    C string with ISO 3166-1 ALPHA-2 language code
//		word (out)			    pointer to C string with trustword UTF-8 encoded
//							    NULL if language is not supported or trustword
//							    wordlist is damaged or unavailable
//		wsize (out)			    length of trustword
//
//	return value:
//	    PEP_STATUS_OK           trustword retrieved
//	    PEP_TRUSTWORD_NOT_FOUND  trustword not found
//
//	caveat:
//		the word pointer goes to the ownership of the caller
//      the caller is responsible to free() it (on Windoze use pEp_free())

DYNAMIC_API PEP_STATUS trustword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        );


// trustwords() - get trustwords for a string of hex values of a fingerprint
//
//	parameters:
//		session (in)		session handle
//		fingerprint (in)	C string with hex values to find trustwords for
//		lang (in)			C string with ISO 3166-1 ALPHA-2 language code
//		words (out)			pointer to C string with trustwords UTF-8 encoded,
//		                    separated by a blank each
//							NULL if language is not supported or trustword
//							wordlist is damaged or unavailable
//		wsize (out)			length of trustwords string
//		max_words (in)		only generate a string with max_words;
//							if max_words == 0 there is no such limit
//
//	return value:
//	    PEP_STATUS_OK           trustwords retrieved
//      PEP_OUT_OF_MEMORY       out of memory
//	    PEP_TRUSTWORD_NOT_FOUND at least one trustword not found
//
//	caveat:
//		the word pointer goes to the ownership of the caller
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


typedef enum _PEP_comm_type {
    PEP_ct_unknown = 0,

    // range 0x01 to 0x09: no encryption, 0x0a to 0x0e: nothing reasonable

    PEP_ct_no_encryption = 0x01,                // generic
    PEP_ct_no_encrypted_channel = 0x02,
    PEP_ct_key_not_found = 0x03,
    PEP_ct_key_expired = 0x04,
    PEP_ct_key_revoked = 0x05,
    PEP_ct_key_b0rken = 0x06,
    PEP_ct_my_key_not_included = 0x09,

    PEP_ct_security_by_obscurity = 0x0a,
    PEP_ct_b0rken_crypto = 0x0b,
    PEP_ct_key_too_short = 0x0e,

    PEP_ct_compromized = 0x0f,                  // known compromized connection

    // range 0x10 to 0x3f: unconfirmed encryption

    PEP_ct_unconfirmed_encryption = 0x10,       // generic
    PEP_ct_OpenPGP_weak_unconfirmed = 0x11,	    // RSA 1024 is weak

    PEP_ct_to_be_checked = 0x20,                // generic
    PEP_ct_SMIME_unconfirmed = 0x21,
    PEP_ct_CMS_unconfirmed = 0x22,

    PEP_ct_strong_but_unconfirmed = 0x30,       // generic
    PEP_ct_OpenPGP_unconfirmed = 0x38,          // key at least 2048 bit RSA or EC
    PEP_ct_OTR_unconfirmed = 0x3a,

    // range 0x40 to 0x7f: unconfirmed encryption and anonymization

    PEP_ct_unconfirmed_enc_anon = 0x40,         // generic
    PEP_ct_PEP_unconfirmed = 0x7f,

    PEP_ct_confirmed = 0x80,                    // this bit decides if trust is confirmed

    // range 0x81 to 0x8f: reserved
    // range 0x90 to 0xbf: confirmed encryption

    PEP_ct_confirmed_encryption = 0x90,         // generic
	PEP_ct_OpenPGP_weak = 0x91,                 // RSA 1024 is weak

    PEP_ct_to_be_checked_confirmed = 0xa0,      //generic
    PEP_ct_SMIME = 0xa1,
    PEP_ct_CMS = 0xa2,

    PEP_ct_strong_encryption = 0xb0,            // generic
	PEP_ct_OpenPGP = 0xb8,                      // key at least 2048 bit RSA or EC
	PEP_ct_OTR = 0xba,

    // range 0xc0 to 0xff: confirmed encryption and anonymization

    PEP_ct_confirmed_enc_anon = 0xc0,           // generic
	PEP_ct_pEp = 0xff
} PEP_comm_type;

typedef struct _pEp_identity {
	size_t struct_size;			// size of whole struct
	char *address;		        // C string with address UTF-8 encoded
	size_t address_size;		// size of address
	char *fpr;			        // C string with fingerprint UTF-8 encoded
	size_t fpr_size;			// size of fingerprint
	char *user_id;		        // C string with user ID UTF-8 encoded
	size_t user_id_size;		// size of user ID
	char *username;		        // C string with user name UTF-8 encoded
	size_t username_size;		// size of user name
	PEP_comm_type comm_type;	// type of communication with this ID
    char lang[3];				// language of conversation
                                // ISO 639-1 ALPHA-2, last byte is 0
    bool me;                    // if this is the local user herself/himself
} pEp_identity;


// new_identity() - allocate memory and set the string and size fields
//
//  parameters:
//      address (in)        UTF-8 string or NULL 
//      fpr (in)            UTF-8 string or NULL 
//      user_id (in)        UTF-8 string or NULL 
//      username (in)       UTF-8 string or NULL 
//
//  return value:
//      pEp_identity struct with correct size values or NULL if out of memory
//
//  caveat:
//      the strings are copied; the original strings are still being owned by
//      the caller

DYNAMIC_API pEp_identity *new_identity(
        const char *address, const char *fpr, const char *user_id,
        const char *username
    );


// identity_dup() - allocate memory and set the string and size fields
//
//  parameters:
//      src (in)            identity to duplicate
//
//  return value:
//      pEp_identity struct with correct size values or NULL if out of memory
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
//	parameters:
//		session (in)		session handle
//		address (in)		C string with communication address, UTF-8 encoded
//		identity (out)		pointer to pEp_identity structure with results or
//		                    NULL if failure
//
//	caveat:
//	    the address string is being copied; the original string remains in the
//	    ownership of the caller
//		the resulting pEp_identity structure goes to the ownership of the
//		caller and has to be freed with free_identity() when not in use any
//		more

DYNAMIC_API PEP_STATUS get_identity(
        PEP_SESSION session, const char *address,
        pEp_identity **identity
    );


// set_identity() - set identity information
//
//	parameters:
//		session (in)		session handle
//		identity (in)		pointer to pEp_identity structure
//
//	return value:
//		PEP_STATUS_OK = 0			    encryption and signing succeeded
//		PEP_CANNOT_SET_PERSON		    writing to table person failed
//		PEP_CANNOT_SET_PGP_KEYPAIR	    writing to table pgp_keypair failed
//		PEP_CANNOT_SET_IDENTITY		    writing to table identity failed
//		PEP_COMMIT_FAILED			    SQL commit failed
//
//	caveat:
//		in the identity structure you need to set the const char * fields to
//		UTF-8 C strings
//		the size fields are ignored

DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    );


// generate_keypair() - generate a new key pair and add it to the key ring
//
//  parameters:
//      session (in)            session handle
//		identity (inout)	    pointer to pEp_identity structure
//
//	return value:
//		PEP_STATUS_OK = 0	    encryption and signing succeeded
//		PEP_ILLEGAL_VALUE       illegal values for identity fields given
//		PEP_CANNOT_CREATE_KEY   key engine is on strike
//
//  caveat:
//      address and username fields must be set to UTF-8 strings
//      the fpr field must be set to NULL
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
//      session (in)            session handle
//      key_data (in)           key data, i.e. ASCII armored OpenPGP key
//      size (in)               amount of data to handle
//
//  return value:
//      PEP_STATUS_OK = 0       key was successfully imported
//      PEP_OUT_OF_MEMORY       out of memory
//      PEP_ILLEGAL_VALUE       there is no key data to import

DYNAMIC_API PEP_STATUS import_key(PEP_SESSION session, const char *key_data, size_t size);


// export_key() - export ascii armored key
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                key id or fingerprint of key
//      key_data (out)          ASCII armored OpenPGP key
//      size (out)               amount of data to handle
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
//	    the ownerships of keylist isgoing to the caller
//	    the caller must use free_stringlist() to free it


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


// get_trust() - get the trust level a key has for a person
//
//  parameters:
//      session (in)            session handle
//      identity (inout)        user_id and fpr to check as UTF-8 strings (in)
//                              user_id and comm_type as result (out)
//
//  this function modifies the given identity struct; the struct remains in
//  the ownership of the caller
//  if the trust level cannot be determined identity->comm_type is set
//  to PEP_ct_unknown

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity);


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
//      key_compromized() of keymanagement API

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
//      expired (out)           flag if key expired

DYNAMIC_API PEP_STATUS key_expired(
        PEP_SESSION session,
        const char *fpr,
        bool *expired
    );


#ifdef __cplusplus
}
#endif
