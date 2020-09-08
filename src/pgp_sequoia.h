/**
 * @file    src/pgp_sequoia.h
 * 
 * @brief   Sequoia PGP driver - implements required cryptotech 
 *          functions for the engine using sequoia-pgp
 * 
 * @license GNU General Public License 3.0 - see LICENSE.txt
 * 
 * @see     https://sequoia-pgp.org/
 * @see     https://docs.sequoia-pgp.org/sequoia_ffi/index.html
 */

#pragma once

#include "pEpEngine.h"

/**
 *  <!--       pgp_init()       -->
 *  
 *  @brief      initialise the sequoia driver for this session
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	in_first    true if this is the first pEp session running
 *                          after startup, else false
 *  
 */
PEP_STATUS pgp_init(PEP_SESSION session, bool in_first);

/**
 *  <!--       pgp_release()       -->
 *  
 *  @brief      release resources used by the sequoia driver in this session
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	out_last	true if this is the last extant pEp session
 *                          running, else false
 *  
 */
void pgp_release(PEP_SESSION session, bool out_last);

/**
 *  <!--       pgp_decrypt_and_verify()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*ctext		constchar
 *  @param[in]	csize		size_t
 *  @param[in]	*dsigtext		constchar
 *  @param[in]	dsigsize		size_t
 *  @param[in]	**ptext		char
 *  @param[in]	*psize		size_t
 *  @param[in]	**keylist		stringlist_t
 *  @param[in]	**filename_ptr		char
 *  
 */
PEP_STATUS pgp_decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char** filename_ptr
    );

/**
 *  <!--       pgp_encrypt_and_sign()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*keylist		conststringlist_t
 *  @param[in]	*ptext		constchar
 *  @param[in]	psize		size_t
 *  @param[in]	**ctext		char
 *  @param[in]	*csize		size_t
 *  
 */
PEP_STATUS pgp_encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

/**
 *  <!--       pgp_sign_only()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*ptext		constchar
 *  @param[in]	psize		size_t
 *  @param[in]	**stext		char
 *  @param[in]	*ssize		size_t
 *  
 */
PEP_STATUS pgp_sign_only(
        PEP_SESSION session, const char* fpr, const char *ptext,
        size_t psize, char **stext, size_t *ssize
    );

/**
 *  <!--       pgp_encrypt_only()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*keylist		conststringlist_t
 *  @param[in]	*ptext		constchar
 *  @param[in]	psize		size_t
 *  @param[in]	**ctext		char
 *  @param[in]	*csize		size_t
 *  
 */
PEP_STATUS pgp_encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );


/**
 *  <!--       pgp_verify_text()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*text		constchar
 *  @param[in]	size		size_t
 *  @param[in]	*signature		constchar
 *  @param[in]	sig_size		size_t
 *  @param[in]	**keylist		stringlist_t
 *  
 */
PEP_STATUS pgp_verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );

/**
 *  <!--       pgp_delete_keypair()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  
 */
PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr);

/**
 *  <!--       pgp_export_keydata()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	**key_data		char
 *  @param[in]	*size		size_t
 *  @param[in]	secret		bool
 *  
 */
PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
    );

/**
 *  <!--       pgp_find_keys()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*pattern		constchar
 *  @param[in]	**keylist		stringlist_t
 *  
 */
PEP_STATUS pgp_find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

/**
 *  <!--       pgp_list_keyinfo()       -->
 *  
 *  @brief  Find all keys (in <fpr, OpenPGP uid> pairs which match this fpr
 *          or other OpenPGP userid pattern
 *  
 *  @param[in]	    session		        PEP_SESSION
 *  @param[in]	    pattern	            Pattern to search for; could be empty, 
 *                                      an fpr, or a mailbox (email, URI, etc).
 *  @param[in,out]	keyinfo_list		A list of <fpr, OpenPGP userid> tuples for the
 *                                      matching keys.
 *   
 *  @note       This function filters out revoked keys, but NOT expired keys.
 */
PEP_STATUS pgp_list_keyinfo(
        PEP_SESSION session, const char* pattern, stringpair_list_t** keyinfo_list
    );

/**
 *  <!--       pgp_generate_keypair()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*identity		pEp_identity
 *  
 */
PEP_STATUS pgp_generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    );

/**
 *  <!--       pgp_get_key_rating()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*comm_type		PEP_comm_type
 *  
 */
PEP_STATUS pgp_get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );

PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents,
                              stringlist_t** imported_keys,
                              uint64_t* changed_key_index);

/**
 *  <!--       pgp_import_private_keydata()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*key_data		constchar
 *  @param[in]	size		size_t
 *  @param[in]	**private_idents		identity_list
 *  
 */
PEP_STATUS pgp_import_private_keydata(PEP_SESSION session, const char *key_data,
                                      size_t size, identity_list **private_idents);

/**
 *  <!--       pgp_recv_key()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*pattern		constchar
 *  
 */
PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern);
/**
 *  <!--       pgp_send_key()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*pattern		constchar
 *  
 */
PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern);

/**
 *  <!--       pgp_renew_key()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*ts		consttimestamp
 *  
 */
PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    );

/**
 *  <!--       pgp_revoke_key()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*reason		constchar
 *  
 */
PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    );

/**
 *  <!--       pgp_key_expired()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	when		consttime_t
 *  @param[in]	*expired		bool
 *  
 */
PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    );

/**
 *  <!--       pgp_key_revoked()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*revoked		bool
 *  
 */
PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    );

/**
 *  <!--       pgp_key_created()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*created		time_t
 *  
 */
PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    );

/**
 *  <!--       pgp_contains_priv_key()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*fpr		constchar
 *  @param[in]	*has_private		bool
 *  
 */
PEP_STATUS pgp_contains_priv_key(
        PEP_SESSION session, 
        const char *fpr,
        bool *has_private);

/**
 *  <!--       pgp_find_private_keys()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	*pattern		constchar
 *  @param[in]	**keylist		stringlist_t
 *  
 */
PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
);

/**
 *  <!--       pgp_binary()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	**path		constchar
 *  
 */
PEP_STATUS pgp_binary(const char **path);

/**
 *  <!--       pgp_config_cipher_suite()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	session		PEP_SESSION
 *  @param[in]	suite		PEP_CIPHER_SUITE
 *  
 */
PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);

#define PGP_BINARY_PATH pgp_binary
