/**
 * @file    media_key.h
 * @brief   Media key support
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef MEDIA_KEY_H
#define MEDIA_KEY_H

#include "pEpEngine.h"
#include "message_api.h"
#include "stringpair.h" // for stringpair_list_t

#ifdef __cplusplus
extern "C" {
#endif


/* Introduction
 * ***************************************************************** */

/* A media key, when available, is used to encrypt otherwise unprotected
   messages.  In the intended use case a media key is shared (off-band) by the
   identities belonging to the same domain.

   The pattern of valid addresses covered by the same media key can be expressed
   in Unix wildcard syntax, as supported by the fnmatch(3) function.
   
   The key is an ordinary pEp key, identitied by an FPR; the key material is
   held in the key database like for any other key.

   A media-key configuration consists in a “map”.  A map is an associative
   data structure made up by
     <address-pattern, key-fpr>
   bindings.  When searching for the media key of an address pattern, the
   first match wins.
   It is natural to implement this simple associative data structure as a
   stringpair_list_t object.

   A map is empty on session initialisation. */


/* Initialisation and finalisation.
 * ***************************************************************** */

/* There is no need for an explicit finalisation here: the initial list will be
   a NULL pointer, and init() will set session fields to NULL for free.  */

/**
 *  <!--       media_key_finalise_map()       -->
 *
 *  @brief Finalise the map, freeing memory.
 *
 *  @param[in]   session          session
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     NULL session
 *
 */
PEP_STATUS media_key_finalize_map(PEP_SESSION session);


/* Configuration.
 * ***************************************************************** */

/* It is more convenient for the config API to have just one function to call
   with a single list-or-pair parameters, rather than two insert/remove
   functions. */

/**
 *  <!--       config_media_keys()       -->
 *
 *  @brief Replace the session map with the given map.
 *
 *  @param[in]   session   session
 *  @param[in]   new_map   an list of pairs <pattern, media key FPR>,
 *                         to be searched for in order with the first
 *                         match winning.
 *                         Pairs must not be NULL, and no key or value
 *                         must be NULL; however the entire list is allowed
 *                         to be NULL.
 *                         Address patterns may contain the Unix-style
 *                         wildcards '?' and '*', and an optional "mailto:"
 *                         prefix.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     session NULL, any address pattern or FPR
 *                                NULL, any FPR is an empty string.  Notice
 *                                that the entire map is allowed to be NULL
 *                                and so is any pair in the map.
 *  @retval PEP_OUT_OF_MEMORY     memory allocation failed
 *
 */
DYNAMIC_API PEP_STATUS config_media_keys(PEP_SESSION session,
                                         const stringpair_list_t *new_map);


/* Configuration: internal functions.
 * ***************************************************************** */

/**
 *  <!--       media_key_insert()       -->
 *
 *  @brief Enrich the media-key map of the given session by appending a
 *         binding; on lookup bindings will be tested in the order of their
 *         insertion, with the first match taking precedence.
 *         The key material can be imported like any other key by calling
 *         import_key or import_key_with_fpr_return .
 *
 *  @param[in]   session          session
 *  @param[in]   address_pattern  an address pattern which may contain
 *                                the Unix-style wildcards '?' and '*'.
 *  @param[in]   fpr              FPR for the key used for every address
 *                                matching the pattern
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL, FPR is an empty string
 *  @retval PEP_OUT_OF_MEMORY     memory allocation failed
 *
 */
PEP_STATUS media_key_insert(PEP_SESSION session,
                            const char *address_pattern,
                            const char *fpr);

/**
 *  <!--       media_key_remove()       -->
 *
 *  @brief Remove every entry from the media-key map of the given session
 *         whose address pattern exactly matches the given string.
 *
 *  @param[in]   session          session
 *  @param[in]   address_pattern  an address pattern which may contain
 *                                the Unix-style wildcards '?' and '*'.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL
 *  @retvat PEP_KEY_NOT_FOUND     no match (the map is not changed in this case)
 *
 */
PEP_STATUS media_key_remove(PEP_SESSION session,
                            const char *address_pattern);


/* Lookup.
 * ***************************************************************** */

/**
 *  <!--       media_key_lookup_address()       -->
 *
 *  @brief Given a session and an address find the matching key FPR in the
 *         session map, if any.
 *         A "mailto:" prefix in the address or in map patterns, if present,
 *         is siltenly ignored.
 *
 *  @param[in]   session          session
 *  @param[in]   address          the address being looked up
 *  @param[out]  fpr_result       the FPR for the first match in the map;
 *                                ownership goes to the caller.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_KEY_NOT_FOUND     no match was found
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL
 *  @retval PEP_OUT_OF_MEMORY     memory allocation of the result failed
 *
 */
PEP_STATUS media_key_lookup_address(PEP_SESSION session,
                                    const char *address,
                                    char **fpr_result);

/**
 *  <!--       media_key_has_identity_a_media_key()       -->
 *  @brief Check whether the address in the given identity has a media key,
 *         setting a Boolean.
 *         Notice that, differently from media_key_lookup_address, this
 *         can never return PEP_KEY_NOT_FOUND, and having the Boolean result
 *         set to false is not an error.
 *         This checks the media key map in the session, and not the management
 *         database.
 *
 *  @param[in]   session          session
 *  @param[in]   identity         the identity whose address we are checking
 *  @param[out]  has_media_key    set to true if a known media key exists;
 *                                undefined on error.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL
 *  @retval PEP_OUT_OF_MEMORY     memory allocation of the result failed
 *
 */
PEP_STATUS media_key_has_identity_a_media_key(PEP_SESSION session,
                                              const pEp_identity *identity,
                                              bool *has_media_key);


/* Media-key-related helpers for other subsystems.
 * ***************************************************************** */

/**
 *  <!--       identity_known_to_use_pEp()       -->
 *
 *  @brief Check whether the given identity is known to use pEp, without
 *         altering it.  Even an unknown identity may be known to use pEp,
 *         thanks to media keys.
 *
 *  @param[in]   session          session
 *  @param[in]   identity         the identity being checked
 *  @param[out]  known_to_use_pEp a Boolean.  Of course false means that
 *                                we have no information, and in fact the
 *                                identity might use pEp.
 *                                Undefined on error.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL
 *  @retval PEP_OUT_OF_MEMORY     memory allocation failed
 *          possibly other failures relayed from get_identity failures
 *
 */
PEP_STATUS identity_known_to_use_pEp(PEP_SESSION session,
                                     const pEp_identity *identity,
                                     bool *known_to_use_pEp);


/**
 *  <!--       amend_identity_with_media_key_information()       -->
 *
 *  @brief Update the given identity, adding information about media key if
 *         needed: in particular any user with a media key is a pEp user
 *         accepting encrypted message and pEp protocol v2.1 (current at the
 *         time of this feature introduction).
 *         Notice that not having a media key is not an error.
 *         This is used internally as part of update_identity .
 *
 *  @param[in]    session         session
 *  @param[inout] identity        the identity to amend
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL
 *  @retval PEP_OUT_OF_MEMORY     memory allocation failed
 *
 */
PEP_STATUS amend_identity_with_media_key_information(PEP_SESSION session,
                                                     pEp_identity *identity);


/* Policy.
 * ***************************************************************** */

/* The rating of a message protected (only) by a media key. */
extern const PEP_rating media_key_message_rating;

/* The comm_type for an identity only known for using a media key.  This is
   useful for determining the colour of an outgoing message. */
extern const PEP_comm_type media_key_comm_type;

/* The enc_format of an outgoing message protected by a media key. */
extern const PEP_enc_format media_key_enc_format;


/**
 *  <!--       media_key_is_there_a_media_key_in()       -->
 *  @brief Check if the keylist contains at least one known media key.
 *
 *  @param[in]   session          session
 *  @param[in]   keylist          a list of key FPRs
 *  @param[out]  found            True iff the key list contains at least one
 *                                known
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_ILLEGAL_VALUE     session or found NULL
 *
 */
PEP_STATUS media_key_is_there_a_media_key_in(PEP_SESSION session,
                                             const stringlist_t *keylist,
                                             bool *found);


/**
 *  <!--       media_key_for_outgoing_message()       -->
 *
 *  @brief Given an outgoing message check if it is possible to use a known
 *         media key suitable to every recipient; if so set the fpr_result
 *         output parameter.
 *         As of now the presence of any Bcc recipient prevents the use of
 *         media keys.  This can be solved later with more sophisticated
 *         handling of Bcc recipients.
 *
 *  @param[in]   session          session
 *  @param[in]   msg              the outgoing message being checked
 *  @param[out]  fpr_result       unless NULL, the FPR for the first match in
 *                                the map; ownership goes to the caller.
 *                                when NULL the function is only used for its
 *                                return value.
 *
 *  @retval PEP_STATUS_OK         success
 *  @retval PEP_KEY_NOT_FOUND     no suitable (single) media key was found;
 *                                in this case the output FPR is also set to
 *                                NULL
 *  @retval PEP_ILLEGAL_VALUE     any argument NULL, message not outgoing
 *  @retval PEP_OUT_OF_MEMORY     memory allocation failed
 *
 */
PEP_STATUS media_key_for_outgoing_message(PEP_SESSION session,
                                          const message *msg,
                                          char **fpr_result);


#ifdef __cplusplus
}
#endif

#endif // #ifndef MEDIA_KEY_H
