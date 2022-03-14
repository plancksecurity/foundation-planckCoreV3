/**
 * @internal
 * @file    src/pgp_netpgp.h
 * 
 * @brief   NETPGP driver - implements required cryptotech 
 *          functions for the engine using netpgp with SSL 
 * 
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PGP_PEP_NETPGP_H
#define PGP_PEP_NETPGP_H

#include "pEpEngine.h"

/**
 *  @internal
 *  <!--       pgp_init()       -->
 *  
 *  @brief      initialise the netpgp driver for this session
 *  
 *  @param[in]  session     session handle
 *  @param[in]  in_first    true if this is the first pEp session running
 *                          after startup, else false
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_init(PEP_SESSION session, bool in_first);

/**
 *  @internal
 *  <!--       pgp_release()       -->
 *  
 *  @brief      release resources used by the netpgp driver in this session
 *  
 *  @param[in]  session     session handle 
 *  @param[in]  out_last    true if this is the last extant pEp session
 *                          running, else false
 *  
 */
void pgp_release(PEP_SESSION session, bool out_last);

/**
 *  @internal
 *  <!--       pgp_decrypt_and_verify()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session       session handle 
 *  @param[in]  ctext         const char*
 *  @param[in]  csize         size_t
 *  @param[in]  dsigtext      const char*
 *  @param[in]  dsigsize      size_t
 *  @param[in]  ptext         char**
 *  @param[in]  psize         size_t*
 *  @param[in]  keylist       stringlist_t**
 *  @param[in]  filename_ptr  char**
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        const char *dsigtext, size_t dsigsize,
        char **ptext, size_t *psize, stringlist_t **keylist,
        char** filename_ptr
    );

/**
 *  @internal
 *  <!--       pgp_encrypt_and_sign()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]   session      session handle 
 *  @param[in]   keylist      const stringlist_t*
 *  @param[in]   ptext        const char*
 *  @param[in]   psize        size_t
 *  @param[out]  ctext        char**
 *  @param[out]  csize        size_t*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );

/**
 *  @internal
 *  <!--       pgp_sign_only()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]   session        session handle 
 *  @param[in]   fpr            const char*
 *  @param[in]   ptext          const char*
 *  @param[in]   psize          size_t
 *  @param[out]  stext          char**
 *  @param[out]  ssize          size_t*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_sign_only(
        PEP_SESSION session, const char* fpr, const char *ptext,
        size_t psize, char **stext, size_t *ssize
    );

/**
 *  @internal
 *  <!--       pgp_encrypt_only()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]   session        session handle 
 *  @param[in]   keylist        const stringlist_t*
 *  @param[in]   ptext          const char*
 *  @param[in]   psize          size_t
 *  @param[out]  ctext          char**
 *  @param[out]  csize          size_t*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    );


/**
 *  @internal
 *  <!--       pgp_verify_text()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session      session handle 
 *  @param[in]  text         const char*
 *  @param[in]  size         size_t
 *  @param[in]  signature    const char*
 *  @param[in]  sig_size     size_t
 *  @param[in]  keylist      stringlist_t**
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    );

/**
 *  @internal
 *  <!--       pgp_delete_keypair()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     session handle 
 *  @param[in]  fpr         const char*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr);

/**
 *  @internal
 *  <!--       pgp_export_keydata()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     session handle 
 *  @param[in]  fpr         const char*
 *  @param[in]  key_data    char**
 *  @param[in]  size        size_t*
 *  @param[in]  secret      bool
 *  
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret
    );

/**
 *  @internal
 *  <!--       pgp_find_keys()       -->
 *  
 *  @brief  Find all keys (as fpr strings) which match this fpr or OpenPGP 
 *          userid pattern
 * 
 *  @param[in]        session                session handle 
 *  @param[in]        pattern                Pattern to search for; could be empty,
 *                                           an fpr, or a mailbox (email, URI, etc).
 *  @param[in,out]    keylist                A list of fprs containing matching keys.
 *  
 *  @note   Unlike pgp_list_keyinfo, this function returns revoked keys.
 * 
 *  @see    pgp_list_keyinfo()
 */
PEP_STATUS pgp_find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    );

/**
 *  @internal
 *  <!--       pgp_list_keyinfo()       -->
 *  
 *  @brief  Find all keys (returning <fpr, OpenPGP uid> pairs) which match this fpr
 *          or OpenPGP userid pattern
 *  
 *  @param[in]        session                session handle 
 *  @param[in]        pattern                Pattern to search for; could be empty,
 *                                           an fpr, or a mailbox (email, URI, etc).
 *  @param[in,out]    keyinfo_list           A list of <fpr, OpenPGP userid> tuples for the
 *                                           matching keys.
 *   
 *  @note       This function filters out revoked keys, but NOT expired keys.
 */
PEP_STATUS pgp_list_keyinfo(
        PEP_SESSION session, const char* pattern, stringpair_list_t** keyinfo_list
    );

/**
 *  @internal
 *  <!--       pgp_generate_keypair()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  identity       pEp_identity*
 *  
 */
PEP_STATUS pgp_generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    );

/**
 *  @internal
 *  <!--       pgp_get_key_rating()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session       session handle 
 *  @param[in]  fpr           const char*
 *  @param[in]  comm_type     PEP_comm_type*
 *  
 */
PEP_STATUS pgp_get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    );

/**
 *  @internal
 *  <!--       pgp_import_keydata()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session              session handle 
 *  @param[in]  key_data             const char *
 *  @param[in]  size                 size_t
 *  @param[in]  private_idents       identity_list **
 *  @param[in]  imported_keys        stringlist_t **
 *  @param[in]  changed_key_index    uint64_t *
 *  
 */
PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents,
                              stringlist_t** imported_keys,
                              uint64_t* changed_key_index);

/**
 *  @internal
 *  <!--       pgp_import_private_keydata()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session         session handle 
 *  @param[in]  key_data        const char*
 *  @param[in]  size            size_t
 *  @param[in]  private_idents  identity_list**
 *  
 */
PEP_STATUS pgp_import_private_keydata(PEP_SESSION session, const char *key_data,
                                      size_t size, identity_list **private_idents);

/**
 *  @internal
 *  <!--       pgp_recv_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session         session handle 
 *  @param[in]  pattern         const char*
 *  
 */
PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern);
/**
 *  @internal
 *  <!--       pgp_send_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session         session handle 
 *  @param[in]  pattern         const char*
 *  
 */
PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern);

/**
 *  @internal
 *  <!--       pgp_renew_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     session handle 
 *  @param[in]  fpr         const char*
 *  @param[in]  ts          const timestamp*
 *  
 */
PEP_STATUS pgp_renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    );

/**
 *  @internal
 *  <!--       pgp_revoke_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  fpr            const char*
 *  @param[in]  reason         const char*
 *  
 */
PEP_STATUS pgp_revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    );

/**
 *  @internal
 *  <!--       pgp_key_expired()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  fpr            const char*
 *  @param[in]  when           const time_t
 *  @param[in]  expired        bool*
 *  
 */
PEP_STATUS pgp_key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    );

/**
 *  @internal
 *  <!--       pgp_key_revoked()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]   session        session handle 
 *  @param[in]   fpr            const char*
 *  @param[out]  revoked        bool*
 *  
 */
PEP_STATUS pgp_key_revoked(
        PEP_SESSION session,
        const char *fpr,
        bool *revoked
    );

/**
 *  @internal
 *  <!--       pgp_key_created()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]   session        session handle 
 *  @param[in]   fpr            const char*
 *  @param[out]  created        time_t*
 *  
 */
PEP_STATUS pgp_key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    );

/**
 *  @internal
 *  <!--       pgp_contains_priv_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  fpr            const char*
 *  @param[in]  has_private    bool*
 *  
 */
PEP_STATUS pgp_contains_priv_key(
        PEP_SESSION session, 
        const char *fpr,
        bool *has_private);

/**
 *  @internal
 *  <!--       pgp_find_private_keys()       -->
 *  
 *  @brief  Find all keys (as fpr strings) which match this fpr or OpenPGP 
 *          userid pattern AND contain a private key
 * 
 *  @param[in]        session                session handle 
 *  @param[in]        pattern                Pattern to search for; could be empty,
 *                                             an fpr, or a mailbox (email, URI, etc).
 *  @param[in,out]    keylist                A list of fprs containing matching keys.
 *  
 *  @note   Unlike pgp_list_keyinfo, this function returns revoked keys.
 * 
 *  @see    pgp_list_keyinfo()
 */
PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist
);

/**
 *  @internal
 *  <!--       pgp_config_cipher_suite()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  suite          PEP_CIPHER_SUITE
 *  
 */
PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite);

#endif
