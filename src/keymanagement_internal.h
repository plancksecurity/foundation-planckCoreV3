/**
 * @file    keymanagement_internal.h
 * @brief   Functions to manage keys (and identities when in relation to keys)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */


#ifndef KEYMANAGEMENT_INTERNAL_H
#define KEYMANAGEMENT_INTERNAL_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  <!--       _myself()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  identity       pEp_identity*
 *  @param[in]  do_keygen      bool
 *  @param[in]  do_renew       bool
 *  @param[in]  ignore_flags   bool
 *  @param[in]  read_only      bool
 *  
 *  @retval PEP_STATUS_OK if identity could be completed or was already complete,
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
PEP_STATUS _myself(PEP_SESSION session, 
                   pEp_identity * identity, 
                   bool do_keygen, 
                   bool do_renew,
                   bool ignore_flags,
                   bool read_only);


/**
 *  <!--       contains_priv_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session       session handle 
 *  @param[in]  fpr           const char*
 *  @param[in]  has_private   bool*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS contains_priv_key(PEP_SESSION session, const char *fpr,
                             bool *has_private);


/**
 *  <!--       get_all_keys_for_user()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session   session handle
 *  @param[in]  user_id   const char*
 *  @param[in]  keys      stringlist_t**
 *  
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_KEY_NOT_FOUND
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS get_all_keys_for_user(PEP_SESSION session, 
                                 const char* user_id,
                                 stringlist_t** keys);



/**
 *  <!--       add_mistrusted_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session   session handle 
 *  @param[in]  fpr       const char*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_CANNOT_SET_PGP_KEYPAIR
 */
PEP_STATUS add_mistrusted_key(PEP_SESSION session, const char* fpr);

/**
 *  <!--       delete_mistrusted_key()       -->
 *  
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  fpr         const char*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_UNKNOWN_ERROR  
 */
PEP_STATUS delete_mistrusted_key(PEP_SESSION session, const char* fpr);
/**
 *  <!--       is_mistrusted_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session      session handle
 *  @param[in]  fpr          const char*
 *  @param[in]  mistrusted   bool*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_UNKNOWN_ERROR  
 */
PEP_STATUS is_mistrusted_key(PEP_SESSION session, const char* fpr, bool* mistrusted);
/**
 *  <!--       get_user_default_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session         session handle
 *  @param[in]  user_id         const char*
 *  @param[in]  default_key     char**
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_GET_KEY_FAILED  
 */
PEP_STATUS get_user_default_key(PEP_SESSION session, const char* user_id,
                                char** default_key);




/**
 *  <!--       get_valid_pubkey()       -->
 *  
 *  @brief            TODO
 *
 * Only call on retrieval of previously stored identity!
 *
 * Also, we presume that if the stored_identity was sent in
 * without an fpr, there wasn't one in the trust DB for this
 * identity.
 *  
 *  @param[in]  session               session handle
 *  @param[in]  stored_identity       pEp_identity*
 *  @param[in]  is_identity_default   bool*
 *  @param[in]  is_user_default       bool*
 *  @param[in]  is_address_default    bool*
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 */
PEP_STATUS get_valid_pubkey(PEP_SESSION session,
                            pEp_identity* stored_identity,
                            bool* is_identity_default,
                            bool* is_user_default,
                            bool* is_address_default);

/**
 *  <!--       get_key_sticky_bit_for_user()       -->
 *
 *  @brief     Get value of sticky bit for this user and key
 *
 *  @param[in]  session       PEP_SESSION
 *  @param[in]  user_id       user_id of key owner to get the sticky bit for
 *  @param[in]  fpr           fingerprint of user's key to consider
 *  @param[out] is_sticky     (by reference) true if sticky bit is set for this user and fpr,
 *                            else false
 *
 */
PEP_STATUS get_key_sticky_bit_for_user(PEP_SESSION session,
                                       const char* user_id,
                                       const char* fpr,
                                       bool* is_sticky);


/**
 *  @internal
 *
 *  <!--       validate_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                     session handle
 *  @param[in]    *ident                        pEp_identity
 *  @param[in]    own_must_contain_private    bool
 *  @param[in]    renew_private                bool
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval PEP_KEY_UNSUITABLE
 *  @retval PEP_PASSPHRASE_REQUIRED
 *  @retval PEP_WRONG_PASSPHRASE
 *  @retval any other value on error
 *
 */
PEP_STATUS validate_fpr(PEP_SESSION session,
                        pEp_identity* ident,
                        bool own_must_contain_private,
                        bool renew_private);

#ifdef __cplusplus
}
#endif

#endif
