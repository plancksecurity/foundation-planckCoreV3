// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"


// pgp_init() - initialize PGP backend
//
//  parameters:
//      session (in)        session handle
//      in_first (in)       true if this is the first session
//
//  return value:
//      PEP_STATUS_OK if PGP backend was successfully initialized
//      or any other value on error

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first);


// pgp_release() - release PGP backend
//
//  paramters:
//      session (in)        session handle
//      out_last (in)       true if this is the last session to release

void pgp_release(PEP_SESSION session, bool out_last);


// pgp_decrypt_and_verify() - decrypt and verify cyphertext
//
//  parameters:
//      session (in)        session handle
//      ctext (in)          bytes with ciphertext
//      csize (in)          size of ciphertext in bytes
//      dsigtext (in)       pointer to bytes with detached signature
//                          or NULL if no detached signature
//      dsigsize (in)       size of detached signature in bytes
//      ptext (out)         bytes with cyphertext
//      psize (out)         size of cyphertext in bytes
//      keylist (out)       list of keys being used; first is the key being
//                          used for signing
//	filename (out)	    PGP filename, when rendered (Optional, only necessary for some PGP implementations (e.g. Symantec),
//                          *** Mostly internal ***
//  return value:
//      PEP_DECRYPTED_AND_VERIFIED      data could be decryped and verified
//      PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH
//                                      a signature does not match
//      PEP_DECRYPTED                   data could be decrypted but not verified
//      PEP_VERIFIED_AND_TRUSTED        data was unencrypted but perfectly signed
//      PEP_VERIFIED                    data was unencrypted, signature matches
//      PEP_DECRYPT_NO_KEY              data could not be decrypted because a
//                                      key is missing
//      PEP_DECRYPT_WRONG_FORMAT        data format not readable
//      PEP_ILLEGAL_VALUE               parameters wrong
//      PEP_OUT_OF_MEMORY               out of memory error
//      PEP_UNKOWN_ERROR                internal error

PEP_STATUS pgp_decrypt_and_verify(
        PEP_SESSION session,
        const char *ctext,
        size_t csize,
        const char *dsigtext,
        size_t dsigsize,
        char **ptext,
        size_t *psize,
        stringlist_t **keylist,
        char** filename_ptr
    );


// pgp_encrypt_and_sign() - encrypt plaintext and sign
//
//  parameters:
//      session (in)        session handle
//      keylist (in)        first key to sign and encrypt, all other keys to
//                          encrypt
//      ptext (in)          bytes with plaintext
//      psize (in)          size of plaintext in bytes
//      ctext (out)         bytes with ciphertext, ASCII armored
//      csize (out)         size of ciphertext in bytes
//
//  return value:
//      PEP_STATUS_OK                   successful
//      PEP_KEY_NOT_FOUND               key not in keyring
//      PEP_KEY_HAS_AMBIG_NAME          multiple keys match data in keylist
//      PEP_GET_KEY_FAILED              access to keyring failed
//      PEP_ILLEGAL_VALUE               parameters wrong
//      PEP_OUT_OF_MEMORY               out of memory error
//      PEP_UNKOWN_ERROR                internal error

PEP_STATUS pgp_encrypt_and_sign(
        PEP_SESSION session,
        const stringlist_t *keylist,
        const char *ptext,
        size_t psize,
        char **ctext,
        size_t *csize
    );


// pgp_encrypt_only() - encrypt plaintext
//
//  parameters:
//      session (in)        session handle
//      keylist (in)        keys to encrypt plaintext
//      ptext (in)          bytes with plaintext
//      psize (in)          size of plaintext in bytes
//      ctext (out)         bytes with ciphertext, ASCII armored
//      csize (out)         size of ciphertext in bytes
//
//  return value:
//      PEP_STATUS_OK                   successful
//      PEP_KEY_NOT_FOUND               key not in keyring
//      PEP_KEY_HAS_AMBIG_NAME          multiple keys match data in keylist
//      PEP_GET_KEY_FAILED              access to keyring failed
//      PEP_ILLEGAL_VALUE               parameters wrong
//      PEP_OUT_OF_MEMORY               out of memory error
//      PEP_UNKNOWN_ERROR                internal error

PEP_STATUS pgp_encrypt_only(
        PEP_SESSION session,
        const stringlist_t *keylist,
        const char *ptext,
        size_t psize,
        char **ctext,
        size_t *csize
    );


// pgp_verify_text() - verify signed data
//
//  parameters:
//      session (in)        session handle
//      keylist (in)        keys to encrypt plaintext
//      text (in)           data to verify, may include signature
//      size (in)           size of data to verify in bytes
//      signature (in)      detached signature data or NULL
//      sig_size (in)       size of detached signature in bytes
//      keylist (out)       list of keys being used for signing
//
//  return value:
//      PEP_VERIFIED_AND_TRUSTED        data was unencrypted but perfectly signed
//                                      this is depending on PGP trust concept
//      PEP_VERIFIED                    data was unencrypted, signature matches
//      PEP_DECRYPT_NO_KEY              data could not be verified because a
//                                      key is missing
//      PEP_DECRYPT_WRONG_FORMAT        data format not readable
//      PEP_ILLEGAL_VALUE               parameters wrong
//      PEP_OUT_OF_MEMORY               out of memory error
//      PEP_UNKOWN_ERROR                internal error

PEP_STATUS pgp_verify_text(
        PEP_SESSION session,
        const char *text,
        size_t size,
        const char *signature,
        size_t sig_size,
        stringlist_t **keylist
    );


// pgp_delete_keypair() - delete key or keypair
//
//  parameters:
//      session (in)        session handle
//      fpr (in)            fingerprint of key or keypair to delete

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr);


// pgp_export_keydata() - export public key data ASCII armored
//
//  parameters:
//      session (in)        session handle
//      fpr (in)            fingerprint of public key to export
//      key_data (out)      ascii armored key data
//      size (out)          size of ascii armored key data
//      secret (in)         additionally export private key data

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session,
        const char *fpr,
        char **key_data,
        size_t *size,
        bool secret
    );


// pgp_find_keys() - find keys where fprs are matching a pattern
//
//  parameters:
//      session (in)        session handle
//      pattern (in)        UTF-8 string with pattern
//      keylist (out)       list of fprs matching

PEP_STATUS pgp_find_keys(
        PEP_SESSION session,
        const char *pattern,
        stringlist_t **keylist
    );


PEP_STATUS pgp_list_keyinfo(
        PEP_SESSION session,
        const char* pattern,
        stringpair_list_t** keyinfo_list
    );

PEP_STATUS pgp_generate_keypair(
        PEP_SESSION session,
        pEp_identity *identity
    );

PEP_STATUS pgp_get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );

PEP_STATUS pgp_import_keydata(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_idents
    );

PEP_STATUS pgp_import_private_keydata(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_idents
    );

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern);

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern);

PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    );

PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    );

PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    );

PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    );

PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    );

PEP_STATUS pgp_contains_priv_key(
        PEP_SESSION session, 
        const char *fpr,
        bool *has_private
    );

PEP_STATUS pgp_find_private_keys(
        PEP_SESSION session,
        const char *pattern,
        stringlist_t **keylist
    );

PEP_STATUS pgp_binary(const char **path);

// Returns first failure status, if there were any. Keys may have been
// imported into DB regardless of status.

PEP_STATUS pgp_import_ultimately_trusted_keypairs(PEP_SESSION session);

/* Really only internal. */
PEP_STATUS pgp_replace_only_uid(
        PEP_SESSION session,
        const char* fpr,
        const char* realname,
        const char* email
    );

#define PGP_BINARY_PATH pgp_binary
