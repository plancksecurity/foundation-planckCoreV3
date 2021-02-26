/**
 * @file    keymanagement.h
 * @brief   Functions to manage keys (and identities when in relation to keys)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */


#ifndef KEYMANAGEMENT_H
#define KEYMANAGEMENT_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  <!--       update_identity()       -->
 *  
 *  @brief Update identity information
 *  
 *  @param[in]     session     session to use
 *  @param[in,out] identity    identity information of communication partner
 *                             (identity->fpr is OUT ONLY), and at least
 *                             .address must be set. 
 *                             If .username is set, it will be used to set or patch
 *                             the username record for this identity.                         
 *  
 *  @retval PEP_STATUS_OK if identity could be updated,
 *  @retval PEP_ILLEGAL_VALUE if called with illegal inputs, including an identity
 *  @retval with .me set or with an own user_id specified in the
 *  @retval *input* (see caveats) 
 *  @retval PEP_KEY_UNSUITABLE if a default key was found for this identity, no
 *  @retval other acceptable keys were found; if this is returned,
 *  @retval the reason for rejecting the first default key found
 *  @retval may be found in the comm_type
 *  @retval any other value on error
 *  
 *  @warning at least identity->address must be a non-empty UTF-8 string as input
 *           update_identity() never writes flags; use set_identity_flags() for
 *           writing
 *           this function NEVER reads the incoming fpr, only writes to it.
 *           this function will fail if called on an identity which, with its input
 *           values, *explicitly* indicates it is an own identity (i.e. .me is set
 *           to true on input, or a user_id is given AND it is a known own user_id).
 *           however, it can RETURN an own identity if this is not indicated a
 *           priori, and in fact will do so with prejudice when not faced with a
 *           matching default (i.e. it is forced to search by address only).
 *           if the identity is known to be an own identity (or the caller wishes
 *           to make it one), call myself() on the identity instead.
 *           FIXME: is this next point accurate?
 *           if this function returns PEP_ct_unknown or PEP_ct_key_expired in
 *           identity->comm_type, the caller must insert the identity into the
 *           asynchronous management implementation, so retrieve_next_identity()
 *           will return this identity later
 *           END FIXME
 *  
 */

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    );

// TODO: remove
// initialise_own_identities () - ensures that an own identity is complete
//
//  parameters:
//      session (in)        session to use
//      my_idents (inout)   identities of local user to quick-set
//                          For these, at least .address must be set.
//                          if no .user_id is set, AND the DB doesn't contain
//                          a default user_id, PEP_OWN_USERID will be used and
//                          become the perennial default for the DB.
//
//  return value:
//      PEP_STATUS_OK if identity could be set,
//      any other value on error
//
//  caveat:
//      this function does NOT generate keypairs. It is intended to
//      precede running of the engine on actual messages. It effectively
//      behaves like myself(), but when there would normally be key generation
//      (when there is no valid key, for example),
//      it instead stores an identity without keys.
//
//      N.B. to adapter devs - this function is likely unnecessary, so please
//      do not put work into exposing it yet. Tickets will be filed if need be.

// DYNAMIC_API PEP_STATUS initialise_own_identities(PEP_SESSION session,
//                                                  identity_list* my_idents);

/**
 *  <!--       myself()       -->
 *  
 *  @brief Ensures that an own identity is complete
 *  
 *  @param[in]     session     session to use
 *  @param[in,out] identity    identity of local user
 *                             both .address and .user_id must be set.
 *                             if .fpr is set, an attempt will be made to make
 *                             that the default key for this identity after key
 *                             validation
 *                             if .fpr is not set, key retrieval is performed
 *                             If .username is set, it will be used to set or patch
 *                             the username record for this identity.                         
 *  
 *  @retval PEP_STATUS_OK if identity could be completed or was already complete,
 *  @retval any other value on error
 *  
 *  @warning If an fpr was entered and is not a valid key, the reason for failure
 *           is immediately returned in the status and, possibly, identity->comm_type
 *           If a default own user_id exists in the database, an alias will 
 *           be created for the default for the input user_id. The ENGINE'S default
 *           user_id is always returned in the .user_id field
 *           myself() NEVER elects keys from the keyring; it will only choose keys
 *           which have been set up explicitly via myself(), or which were imported
 *           during a first time DB setup from an OpenPGP keyring (compatibility only) 
 *           this function generates a keypair on demand; because it's synchronous
 *           it can need a decent amount of time to return
 *           if you need to do this asynchronous, you need to return an identity
 *           with retrieve_next_identity() where pEp_identity.me is true
 *  
 */

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity);

/**
 *  <!--       _myself()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        PEP_SESSION
 *  @param[in]  identity       pEp_identity*
 *  @param[in]  do_keygen      bool
 *  @param[in]  do_renew       bool
 *  @param[in]  ignore_flags   bool
 *  @param[in]  read_only      bool
 *  
 */
PEP_STATUS _myself(PEP_SESSION session, 
                   pEp_identity * identity, 
                   bool do_keygen, 
                   bool do_renew,
                   bool ignore_flags,
                   bool read_only);

/**
 *  <!--       retrieve_next_identity()       -->
 *  
 *  @brief Callback being called by do_keymanagement()
 *  
 *  @param[in]   management    data structure to deliver (implementation defined)
 *  
 *  @retval identity to check or NULL to terminate do_keymanagement()
 *  @retval if given identity must be created with new_identity()
 *  @retval the identity struct is going to the ownership of this library
 *  @retval it must not be freed by the callee
 *  
 *  @warning this callback has to block until an identity or NULL can be returned
 *           an implementation is not provided by this library; instead it has to be
 *           implemented by the user of this library
 *  
 */

typedef pEp_identity *(*retrieve_next_identity_t)(void *management);


/**
 *  <!--       examine_identity()       -->
 *  
 *  @brief Callback for appending to queue
 *  
 *  @param[in]   ident         identity to examine
 *  @param[in]   management    data structure to deliver (implementation defined)
 *  
 *  @retval 0 if identity was added successfully to queue or nonzero otherwise
 *  
 *  
 */

typedef int (*examine_identity_t)(pEp_identity *ident, void *management);


/**
 *  <!--       register_examine_function()       -->
 *  
 *  @brief Register examine_identity() callback
 *  
 *  @param[in]   session             session to use
 *  @param[in]   examine_identity    examine_identity() function to register
 *  @param[in]   management          data structure to deliver (implementation defined)
 *  
 *  
 */

DYNAMIC_API PEP_STATUS register_examine_function(
        PEP_SESSION session, 
        examine_identity_t examine_identity,
        void *management
    );


/**
 *  <!--       do_keymanagement()       -->
 *  
 *  @brief Function to be run on an extra thread
 *  
 *  @param[in]   retrieve_next_identity    pointer to retrieve_next_identity()
 *                                           callback which returns at least a valid
 *                                           address field in the identity struct
 *  
 *  @retval PEP_STATUS_OK if thread has to terminate successfully or any other
 *  @retval value on failure
 *  
 *  @warning to ensure proper working of this library, a thread has to be started
 *           with this function immediately after initialization
 *           do_keymanagement() calls retrieve_next_identity(management)
 *           messageToSend can only be null if no transport is application based
 *           if transport system is not used it must not be NULL
 *  
 */

DYNAMIC_API PEP_STATUS do_keymanagement(
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    );


/**
 *  <!--       key_mistrusted()       -->
 *  
 *  @brief Mark key as being compromised
 *  
 *  @param[in]   session    session to use
 *  @param[in]   ident      person and key which was compromised
 *  
 *  @warning ident is INPUT ONLY. If you want updated trust on the identity, you'll have
 *           to call update_identity or myself respectively after this.
 *           N.B. If you are calling this on a key that is the identity or user default,
 *           it will be removed as the default key for ANY identity and user for which
 *           it is the default. Please keep in mind that the undo in undo_last_mistrust
 *           will only undo the current identity's / it's user's default, not any
 *           other identities which may be impacted (this will not affect most use
 *           cases)
 *  
 */

DYNAMIC_API PEP_STATUS key_mistrusted(
        PEP_SESSION session,
        pEp_identity *ident
    );

/**
 *  <!--       trust_personal_key()       -->
 *  
 *  @brief Mark a key as trusted for a user
 *  
 *  @param[in]   session    session to use
 *  @param[in]   ident      person and key to trust in - this must not be an
 *                            own_identity in which the .me flag is set or
 *                            the user_id is an own user_id.
 *  
 *  @warning the fields user_id, address and fpr must be supplied
 *           own identities will result in a return of PEP_ILLEGAL_VALUE.
 *           for non-own users, this will 1) set the trust bit on its comm type in the DB,
 *           2) set this key as the identity default if the current identity default
 *           is not trusted, and 3) set this key as the user default if the current
 *           user default is not trusted.
 *  
 */

DYNAMIC_API PEP_STATUS trust_personal_key(
        PEP_SESSION session,
        pEp_identity *ident
    );

/**
 *  <!--       trust_own_key()       -->
 *  
 *  @brief Mark a key as trusted for self, generally
 *         used when we need to trust a public key
 *         associated with outselves for issues like
 *         manual key import
 *  
 *  @param[in]   session    session to use
 *  @param[in]   ident      own ident containing fpr to trust
 *  
 *  @warning if this is a public key only, keep in mind that if
 *           the private part of the keypair is later added,
 *           it will not undergo separate trust evaluation. This
 *           is fine - even desired - as long as the semantics
 *           of this function are understood as both trusting
 *           the key and verifying it as an own key. This will
 *           NEVER cause replacement of or setting of a default
 *           *alone*. However, if a private key is ever associated
 *           with this fpr, please keep in mind that trusting it
 *           here makes it an eligible key for selection for    
 *           encryption later. So use this function on purpose with
 *           an understanding of what you're doing!
 *  
 */
DYNAMIC_API PEP_STATUS trust_own_key(
        PEP_SESSION session,
        pEp_identity *ident
    );


/**
 *  <!--       key_reset_trust()       -->
 *  
 *  @brief Reset trust bit or explicitly mistrusted status for an identity and
 *         its accompanying key/user_id pair.
 *  
 *  @param[in]   session    session to use
 *  @param[in]   ident      identity for person and key whose trust status is to be reset
 *  
 *  @warning ident is INPUT ONLY. If you want updated trust on the identity, you'll have
 *           to call update_identity or myself respectively after this.
 *           N.B. If you are calling this on a key that is the identity or user default,
 *           it will be removed as the default key for the identity and user (but is still
 *           available for key election, it is just not the cached default anymore)
 *  
 */

DYNAMIC_API PEP_STATUS key_reset_trust(
        PEP_SESSION session,
        pEp_identity *ident
    );

/**
 *  <!--       own_key_is_listed()       -->
 *  
 *  @brief Returns true id key is listed as own key
 *  
 *  @param[in]     session    session to use
 *  @param[in]     fpr        fingerprint of key to test
 *  @param[out]    listed     flags if key is own
 *  
 *  
 */

DYNAMIC_API PEP_STATUS own_key_is_listed(
        PEP_SESSION session,
        const char *fpr,
        bool *listed
    );


/**
 *  <!--       _own_identities_retrieve()       -->
 *  
 *  @brief Retrieve all own identities
 *  
 *  @param[in]     session           session to use
 *  @param[out]    own_identities    list of own identities
 *                                   excluded_flags (int)    flags to exclude from results
 *  
 *  @warning the ownership of the copy of own_identities goes to the caller
 *  
 */

DYNAMIC_API PEP_STATUS _own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities,
        identity_flags_t excluded_flags
    );

/**
 *  <!--       own_identities_retrieve()       -->
 *  
 *  @brief Retrieve all own identities
 *  
 *  @param[in]     session           session to use
 *  @param[out]    own_identities    list of own identities
 *  
 *  @warning the ownership of the copy of own_identities goes to the caller
 *  
 */

DYNAMIC_API PEP_STATUS own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities
    );

/**
 *  <!--       contains_priv_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session       PEP_SESSION
 *  @param[in]  fpr           const char*
 *  @param[in]  has_private   bool*
 *  
 */
PEP_STATUS contains_priv_key(PEP_SESSION session, const char *fpr,
                             bool *has_private);

/**
 *  <!--       _own_keys_retrieve()       -->
 *  
 *  @brief Retrieve all flagged keypair fingerprints 
 *  
 *  @param[in]   session           session to use
 *  @param[out]  keylist           list of fingerprints
 *  @param[in]   excluded_flags    flags to exclude from results
 *  @param[in]   private_only      if true, return only fprs for
 *                                   which we have the secret part
 *  
 *  @warning the ownership of the list goes to the caller
 *  
 */
DYNAMIC_API PEP_STATUS _own_keys_retrieve(
        PEP_SESSION session,
        stringlist_t **keylist,
        identity_flags_t excluded_flags,
        bool private_only
      );

/**
 *  <!--       own_keys_retrieve()       -->
 *  
 *  @brief Retrieve all flagged public/private keypair fingerprints 
 *  
 *  @param[in]     session    session to use
 *  @param[out]    keylist    list of fingerprints
 *  
 *  @warning the ownership of the list goes to the caller
 *           this function does not return keys without a private key part
 *  
 */
DYNAMIC_API PEP_STATUS own_keys_retrieve(
        PEP_SESSION session,
        stringlist_t **keylist
      );

/**
 *  <!--       set_own_key()       -->
 *  
 *  @brief Mark a key as own key
 *  
 *  @param[in]     session    session to use
 *  @param[in,out] me         own identity this key is used for
 *  @param[in]     fpr        fingerprint of the key to mark as own key
 *  
 *  @warning the key has to be in the key ring already
 *           me->address, me->user_id and me->username must be set to valid data
 *           myself() is called by set_own_key() without key generation
 *           me->flags are ignored
 *           me->address must not be an alias
 *           me->fpr will be ignored and replaced by fpr, but
 *           caller MUST surrender ownership of the me->fpr reference, because 
 *           it may be freed and replaced within the myself call. caller owns 
 *           me->fpr memory again upon return.
 *  
 */

DYNAMIC_API PEP_STATUS set_own_key(
       PEP_SESSION session,
       pEp_identity *me,
       const char *fpr
    );

/**
 *  <!--       set_own_imported_key()       -->
 *
 *  @brief Mark a key as an own default key, test to be sure the private key is
 *         present and can be used, and
 *
 *  @param[in]      session    session to use
 *  @param[in,out]  me         own identity this key is used for
 *  @param[in]      fpr        fingerprint of the key to mark as own key
 *  @param[in]      sticky     boolean, true if we should set a sticky bit so
 *                             it will not be automatically reset by sync and should
 *                             win sync key elections if no other competing key
 *                             for the same identity has its sticky bit set,
 *                             false otherwise
 *
 *  @warning the key has to be in the key ring already
 *           me->address, me->user_id and me->username must be set to valid data
 *           myself() is called by set_own_key() from within this call without key generation
 *           me->flags are ignored
 *           me->address must not be an alias
 *           me->fpr will be ignored and replaced by fpr, but
 *           caller MUST surrender ownership of the me->fpr reference, because
 *           it may be freed and replaced within the myself call. caller owns
 *           me->fpr memory again upon return.
 *           CAN GENERATE A PASSPHRASE REQUEST
 *
 */
DYNAMIC_API PEP_STATUS set_own_imported_key(
        PEP_SESSION session,
        pEp_identity* me,
        const char* fpr,
        bool sticky
    );

//
// clean_own_key_defaults()
//
// Remove any broken, unrenewable expired, or revoked 
// own keys from identity and user defaults in the database.
//  
//  parameters:
//      session (in)          session to use
//
//  return value:
//      PEP_STATUS_OK if all went well
//      PEP_PASSPHRASE_REQUIRED if a key needs to be renewed 
//                              but cached passphrase isn't present 
//      PEP_WRONG_PASSPHRASE if passphrase required for expired key renewal 
//                           but passphrase is the wrong one
//      Otherwise, database and keyring errors as appropriate 
//
/**
 *  <!--       clean_own_key_defaults()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     PEP_SESSION
 *  
 */
DYNAMIC_API PEP_STATUS clean_own_key_defaults(PEP_SESSION session);

/**
 *  <!--       get_all_keys_for_user()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session   PEP_SESSION
 *  @param[in]  user_id   const char*
 *  @param[in]  keys      stringlist_t**
 *  
 */
PEP_STATUS get_all_keys_for_user(PEP_SESSION session, 
                                 const char* user_id,
                                 stringlist_t** keys);


//PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags);

/**
 *  <!--       add_mistrusted_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session   PEP_SESSION
 *  @param[in]  fpr       const char*
 *  
 */
PEP_STATUS add_mistrusted_key(PEP_SESSION session, const char* fpr);
/**
 *  <!--       delete_mistrusted_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     PEP_SESSION
 *  @param[in]  fpr         const char*
 *  
 */
PEP_STATUS delete_mistrusted_key(PEP_SESSION session, const char* fpr);
/**
 *  <!--       is_mistrusted_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session      PEP_SESSION
 *  @param[in]  fpr          const char*
 *  @param[in]  mistrusted   bool*
 *  
 */
PEP_STATUS is_mistrusted_key(PEP_SESSION session, const char* fpr, bool* mistrusted);
/**
 *  <!--       get_user_default_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session         PEP_SESSION
 *  @param[in]  user_id         const char*
 *  @param[in]  default_key     char**
 *  
 */
PEP_STATUS get_user_default_key(PEP_SESSION session, const char* user_id,
                                char** default_key);




// Only call on retrieval of previously stored identity!
// Also, we presume that if the stored_identity was sent in
// without an fpr, there wasn't one in the trust DB for this
// identity.
/**
 *  <!--       get_valid_pubkey()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session               PEP_SESSION
 *  @param[in]  stored_identity       pEp_identity*
 *  @param[in]  is_identity_default   bool*
 *  @param[in]  is_user_default       bool*
 *  @param[in]  is_address_default    bool*
 *  @param[in]  check_blacklist       bool
 *  
 */
PEP_STATUS get_valid_pubkey(PEP_SESSION session,
                            pEp_identity* stored_identity,
                            bool* is_identity_default,
                            bool* is_user_default,
                            bool* is_address_default,
                            bool check_blacklist);


PEP_STATUS get_key_sticky_bit_for_user(PEP_SESSION session,
                                       const char* user_id,
                                       const char* fpr,
                                       bool* is_sticky);

#ifdef __cplusplus
}
#endif

#endif
