/**
 * @internal
 * @file    pEpEngine_internal.h
 * @brief   Exposed internal functions and structures.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_ENGINE_INTERNAL_H
#define PEP_ENGINE_INTERNAL_H

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

/**
 *  @internal
 *  <!--       replace_identities_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  old_fpr     const char*
 *  @param[in]  new_fpr     const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_CANNOT_SET_IDENTITY
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter values
 *
 */
PEP_STATUS replace_identities_fpr(PEP_SESSION session,
                                 const char* old_fpr,
                                 const char* new_fpr);


/**
 *  @internal
 *  <!--       set_trust()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  identity       pEp_identity*
 *
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS set_trust(PEP_SESSION session,
                     pEp_identity* identity);

/**
 *  @internal
 *  <!--       update_trust_for_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session       session handle
 *  @param[in]  fpr           const char*
 *  @param[in]  comm_type     PEP_comm_type
 *
 *
 *  @retval        PEP_STATUS_OK
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval        PEP_CANNOT_SET_TRUST
 *
 */
PEP_STATUS update_trust_for_fpr(PEP_SESSION session,
                                const char* fpr,
                                PEP_comm_type comm_type);


/**
 *  @internal
 *  <!--       get_key_userids()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  fpr            const char*
 *  @param[in]  keylist        stringlist_t**
 *
 */
PEP_STATUS get_key_userids(
        PEP_SESSION session,
        const char* fpr,
        stringlist_t** keylist
    );

/**
 *  @internal
 *  <!--       key_created()       -->
 *
 *  @brief Get creation date of a key
 *
 *  @param[in]     session    session handle
 *  @param[in]     fpr        fingerprint of key
 *  @param[out]    created    date of creation
 *
 *  @retval        PEP_STATUS_OK
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *
 */

PEP_STATUS key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    );

/**
 *  @internal
 *  <!--       find_private_keys()       -->
 *
 *  @brief Find keys in keyring
 *
 *  @param[in]     session    session handle
 *  @param[in]     pattern    fingerprint or address to search for as
 *                            UTF-8 string
 *  @param[out]    keylist    list of fingerprints found or NULL on error
 *
 *  @retval        PEP_STATUS_OK
 *  @retval        PEP_ILLEGAL_VALUE    illegal parameter value
 *
 *  @warning the ownerships of keylist isgoing to the caller
 *           the caller must use free_stringlist() to free it
 *
 */
PEP_STATUS find_private_keys(PEP_SESSION session, const char* pattern,
                             stringlist_t **keylist);


/**
 *  @internal
 *  <!--       _generate_keypair()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session          session handle
 *  @param[in]  identity         pEp_identity*
 *  @param[in]  suppress_event   bool
 *
 *  @retval PEP_STATUS_OK           encryption and signing succeeded
 *  @retval PEP_ILLEGAL_VALUE       illegal values for identity fields given
 *  @retval PEP_CANNOT_CREATE_KEY   key engine is on strike
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval any other value on error
 *
 */
PEP_STATUS _generate_keypair(PEP_SESSION session,
                             pEp_identity *identity,
                             bool suppress_event);

// This is used internally when there is a temporary identity to be retrieved
// that may not yet have an FPR attached. See get_identity() for functionality,
// params and caveats.
/**
 *  @internal
 *  <!--       get_identity_without_trust_check()       -->
 *
 *  @brief      
 *
 * This is used internally when there is a temporary identity to be retrieved
 * that may not yet have an FPR attached. See get_identity() for functionality,
 * params and caveats.
 *
 *  @param[in]  session         session handle
 *  @param[in]  address         const char*
 *  @param[in]  user_id         const char*
 *  @param[in]  identity        pEp_identity**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *
 */
PEP_STATUS get_identity_without_trust_check(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    );

/**
 *  @internal
 *  <!--       get_identities_by_address()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  address        const char*
 *  @param[in]  id_list        identity_list**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *
 */
PEP_STATUS get_identities_by_address(
        PEP_SESSION session,
        const char *address,
        identity_list** id_list
    );

/**
 *  @internal
 *  <!--       get_identities_by_userid()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  user_id        const char*
 *  @param[in]  identities     identity_list**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *
 */
PEP_STATUS get_identities_by_userid(
        PEP_SESSION session,
        const char *user_id,
        identity_list **identities
    );

/**
 *  @internal
 *  <!--       is_own_address()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  address        const char*
 *  @param[in]  is_own_addr    bool*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval     PEP_RECORD_NOT_FOUND
 *
 */
PEP_STATUS is_own_address(PEP_SESSION session,
                          const char* address,
                          bool* is_own_addr);

/**
 *  @internal
 *  <!--       replace_userid()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session         session handle
 *  @param[in]  old_uid         const char*
 *  @param[in]  new_uid         const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_CANNOT_SET_PERSON
 */
PEP_STATUS replace_userid(PEP_SESSION session, const char* old_uid,
                              const char* new_uid);

/**
 *  @internal
 *  <!--       remove_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  fpr         const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_SET_PGP_KEYPAIR
 *
 */
PEP_STATUS remove_key(PEP_SESSION session, const char* fpr);

/**
 *  @internal
 *  <!--       remove_fpr_as_default()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  fpr         const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_SET_IDENTITY
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
PEP_STATUS remove_fpr_as_default(PEP_SESSION session,
                                    const char* fpr);


/**
 *  @internal
 *  <!--       get_main_user_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  user_id        const char*
 *  @param[in]  main_fpr       char**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *  @retval     PEP_KEY_NOT_FOUND
 *  @retval     PEP_CANNOT_FIND_PERSON
 */
PEP_STATUS get_main_user_fpr(PEP_SESSION session,
                             const char* user_id,
                             char** main_fpr);

/**
 *  @internal
 *  <!--       replace_main_user_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  user_id        const char*
 *  @param[in]  new_fpr        const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
PEP_STATUS replace_main_user_fpr(PEP_SESSION session, const char* user_id,
                              const char* new_fpr);

/**
 *  @internal
 *  <!--       replace_main_user_fpr_if_equal()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session         session handle
 *  @param[in]  user_id         const char*
 *  @param[in]  new_fpr         const char*
 *  @param[in]  compare_fpr     const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
PEP_STATUS replace_main_user_fpr_if_equal(PEP_SESSION session, const char* user_id,
                                          const char* new_fpr, const char* compare_fpr);

/**
 *  @internal
 *  <!--       refresh_userid_default_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  user_id        const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
PEP_STATUS refresh_userid_default_key(PEP_SESSION session, const char* user_id);

/**
 *  @internal
 *  <!--       exists_person()       -->
 *
 *  @brief            TODO
 *
 * returns true (by reference) if a person with this user_id exists;
 * Also replaces aliased user_ids by defaults in identity.
 *
 *  @param[in]  session        session handle
 *  @param[in]  identity       pEp_identity*
 *  @param[in]  exists         bool*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE    illegal parameter value
 *  @retval     PEP_UNKNOWN_DB_ERROR
 */
PEP_STATUS exists_person(PEP_SESSION session, pEp_identity* identity, bool* exists);

/**
 *  @internal
 *  <!--       set_pgp_keypair()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  fpr         const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_SET_PGP_KEYPAIR
 */
PEP_STATUS set_pgp_keypair(PEP_SESSION session, const char* fpr);

/**
 *  @internal
 *  <!--       set_protocol_version()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  ident          pEp_identity*
 *  @param[in]  new_ver_major  unsigned int
 *  @param[in]  new_ver_minor  unsigned int
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_SET_PEP_VERSION
 *
 */
PEP_STATUS set_protocol_version(PEP_SESSION session, pEp_identity* ident, unsigned int new_ver_major, unsigned int new_ver_minor);

/**
 *  @internal
 *  <!--       clear_trust_info()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session     session handle
 *  @param[in]  user_id     const char*
 *  @param[in]  fpr         const char*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_UNKNOWN_ERROR
 *
 */
PEP_STATUS clear_trust_info(PEP_SESSION session,
                            const char* user_id,
                            const char* fpr);

/**
 *  @internal
 *  <!--       upgrade_protocol_version_by_user_id()       -->
 *
 *  @brief            TODO
 *
 *  @note Generally ONLY called by set_as_pEp_user, and ONLY from < 2.0 to 2.0.
 *
 *  @param[in]  session        session handle
 *  @param[in]  ident          pEp_identity*
 *  @param[in]  new_ver_major  unsigned int
 *  @param[in]  new_ver_minor  unsigned int
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_SET_PEP_VERSION
 *
 */
PEP_STATUS upgrade_protocol_version_by_user_id(PEP_SESSION session,
        pEp_identity* ident,
        unsigned int new_ver_major,
        unsigned int new_ver_minor
    );

/**
 *  @internal
 *  <!--       set_person()       -->
 *
 *  @brief            TODO
 *
 * exposed for testing
 *
 *  @param[in]  session            session handle
 *  @param[in]  identity           pEp_identity*
 *  @param[in]  guard_transaction  bool
 *
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 */
PEP_STATUS set_person(PEP_SESSION session, pEp_identity* identity,
                      bool guard_transaction);
/**
 *  @internal
 *  <!--       bind_own_ident_with_contact_ident()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  own_ident      pEp_identity*
 *  @param[in]  contact_ident  pEp_identity*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
PEP_STATUS bind_own_ident_with_contact_ident(PEP_SESSION session,
                                             pEp_identity* own_ident,
                                             pEp_identity* contact_ident);

/**
 *  @internal
 *  <!--       get_last_contacted()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  id_list        identity_list**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *
 */
PEP_STATUS get_last_contacted(
        PEP_SESSION session,
        identity_list** id_list
    );

/**
 *  @internal
 *  <!--       get_own_ident_for_contact_id()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]   session        session handle
 *  @param[in]   contact        const pEp_identity*
 *  @param[out]  own_ident      pEp_identity**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *
 */
PEP_STATUS get_own_ident_for_contact_id(PEP_SESSION session,
                                          const pEp_identity* contact,
                                          pEp_identity** own_ident);

/**
 *  @internal
 *  <!--       exists_trust_entry()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]   session        session handle
 *  @param[in]   identity       pEp_identity*
 *  @param[out]  exists         bool*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *
 */
PEP_STATUS exists_trust_entry(PEP_SESSION session, pEp_identity* identity,
                              bool* exists);

/**
 *  @internal
 *  <!--       is_own_key()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]   session        session handle
 *  @param[in]   fpr            const char*
 *  @param[out]  own_key        bool*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *
 */
PEP_STATUS is_own_key(PEP_SESSION session, const char* fpr, bool* own_key);

/**
 *  @internal
 *  <!--       get_identities_by_main_key_id()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]   session      session handle
 *  @param[in]   fpr          const char*
 *  @param[out]  identities   identity_list**
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *
 */
PEP_STATUS get_identities_by_main_key_id(
        PEP_SESSION session,
        const char *fpr,
        identity_list **identities);


PEP_STATUS get_identities_by_address(
        PEP_SESSION session,
        const char *address,
        identity_list** id_list
    );

/**
 *  @internal
 * <!-- get_default_identity_fpr() -->
 *
 * @param[in] session
 * @param[in] address
 * @param[in] user_id
 * @param[out] main_fpr
 * @retval     PEP_STATUS_OK   if fpr was successfully retrieved
 * @retval     error           otherwise
 */
PEP_STATUS get_default_identity_fpr(PEP_SESSION session,
                                    const char* address,
                                    const char* user_id,
                                    char** main_fpr);

/**
 *  @internal
 *  <!--       set_default_identity_fpr()       -->
 *  Set the default key fingerprint for the identity identitified by this address and user_id. Will only
 *  succeed if identity is already in DB.
 *
 *  @param[in]  session     session handle
 *  @param[in]  user_id     user_id for identity - cannot be NULL
 *  @param[in]  address     address for identity - cannot be NULL
 *  @param[in]  fpr         fingerprint for identity - cannot be NULL
 *
 *  @retval     PEP_STATUS_OK   if key was set or identity doesn't exists
 *  @retval     error           otherwise
 */
PEP_STATUS set_default_identity_fpr(PEP_SESSION session,
                                    const char* user_id,
                                    const char* address,
                                    const char* fpr);

/**
 *  @internal
 *  <!--       sign_only()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]   session        session handle
 *  @param[in]   data           const char*
 *  @param[in]   data_size      size_t
 *  @param[in]   fpr            const char*
 *  @param[out]  sign           char**
 *  @param[out]  sign_size      size_t*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *
 */
PEP_STATUS sign_only(PEP_SESSION session,
                     const char *data,
                     size_t data_size,
                     const char *fpr,
                     char **sign,
                     size_t *sign_size);

/**
 *  @internal
 *  <!--       set_all_userids_to_own()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session        session handle
 *  @param[in]  id_list        identity_list*
 *
 */
PEP_STATUS set_all_userids_to_own(PEP_SESSION session,
                                  identity_list* id_list);

/**
 *  @internal
 *  <!--       has_partner_contacted_address()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]  session         session handle
 *  @param[in]  partner_id      const char*
 *  @param[in]  own_address     const char*
 *  @param[in]  was_contacted   bool*
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *
 */
PEP_STATUS has_partner_contacted_address(PEP_SESSION session, const char* partner_id,
                                         const char* own_address, bool* was_contacted);

/*
 *  @internal
 * <!-- exists_identity_entry() -->
 * documented in pEpEngine.c 
 * 
 */
PEP_STATUS exists_identity_entry(PEP_SESSION session, pEp_identity* identity,
                                 bool* exists);

/**
 *  @internal
 * <!-- force_set_identity_username() -->
 * @param[in] 		session		PEP_SESSION
 * @param[in] 	identity 	pEp_identity*
 * @param[in] 		username	const char*
 * @return 		PEP_STATUS
 */
PEP_STATUS force_set_identity_username(PEP_SESSION session, pEp_identity* identity, const char* username);

#ifdef __cplusplus
}
#endif

#endif
