#define _EXPORT_PEP_ENGINE_DLL
#include "media_key.h"

#include "pEp_internal.h"
#include "stringpair.h" // for stringpair_list_t

#include <assert.h>
#include <string.h>


/* Debugging.
 * ***************************************************************** */

//#define DEBUG_MEDIA_KEY

#if ! defined(DEBUG_MEDIA_KEY)
# define fprintf(stream, ...)               \
    do { /* Do nothing. */ } while (false)
#endif


/* Initialisation and finalisation.
 * ***************************************************************** */

PEP_STATUS media_key_finalize_map(PEP_SESSION session) {
    /* Sanity checks. */
    assert(session);
    if(session == NULL)
        return PEP_ILLEGAL_VALUE;

    /* Do the work. */
    free_stringpair_list(session->media_key_map);

    /* Out of defensiveness. */
    session->media_key_map = NULL;
    return PEP_STATUS_OK;
}


/* Utility.
 * ***************************************************************** */

static bool fprs_equal(const char *fpr_a, const char *fpr_b)
{
    return strcmp(fpr_a, fpr_b) == 0;
}

/* Given a non-NULL '\0'-terminated string return either the same string or a
   substring of it without the initial "mailto:" prefix, if such prefix is
   present.  This function performs no allocation or copy: the result is always
   a substring of the argument. */
static const char *normalize_address(const char *address) {
    if (strstr(address, "mailto:") == NULL)
        return address;
    else
        return address + /* strlen("mailto:") */ 7;
}


/* Configuration.
 * ***************************************************************** */

/* Internally I make sure the map is represented as a "normal-form" list,
   without silly NULL value fields; to make sure the map is well-built I build
   it myself, using media_key_insert internally. */

PEP_STATUS media_key_insert(PEP_SESSION session,
                            const char *address_pattern,
                            const char *fpr)
{
    /* Sanity checks. */
    assert(session && address_pattern && fpr && ! EMPTYSTR(fpr));
    if (! (session && address_pattern && fpr && ! EMPTYSTR(fpr)))
        return PEP_ILLEGAL_VALUE;

    /* Work with a normalised version of the address pattern. */
    address_pattern = normalize_address(address_pattern);

    /* Initialise heap-allocated pointers to NULL so that they all have a known
       value in case of allocation failure. */
    char *normalized_fpr = NULL;
    stringpair_t *new_pair = NULL;

    /* Work with a normalised copy of the FPR. */
    size_t fpr_length = strlen(fpr);
    normalized_fpr = malloc(fpr_length + 1);
    if (normalized_fpr == NULL)
        goto out_of_memory;
    int i;
    for (i = 0; i /* <= , to include the trailing '\0' */ <= fpr_length; i ++)
        normalized_fpr [i] = toupper(fpr [i]);

    /* Make the new entry. */
    stringpair_list_t *old_map = session->media_key_map;
    new_pair = new_stringpair(address_pattern, normalized_fpr);
    if (new_pair == NULL)
        goto out_of_memory;
    stringpair_list_t *new_last_element
        = stringpair_list_add(old_map, new_pair);
    if (new_last_element == NULL)
        goto out_of_memory;
    /* Else the structured ponted by old_map is modified destructively, so we
       have nothing else to do as long as the map was not previously NULL... */
    if (old_map == NULL)
        session->media_key_map = new_last_element;
    free(normalized_fpr);
    return PEP_STATUS_OK;

 out_of_memory:
    free(normalized_fpr);
    free(new_pair);
    return PEP_OUT_OF_MEMORY;
}

PEP_STATUS media_key_remove(PEP_SESSION session,
                            const char *address_pattern)
{
    /* Sanity checks. */
    assert(session && address_pattern);
    if (! (session && address_pattern))
        return PEP_ILLEGAL_VALUE;

    /* Work with a normalised version of the address pattern, so that we can
       abstract from "mailto:" prefixes.  The stored address patterns have been
       normalised already. */
    address_pattern = normalize_address(address_pattern);

    /* Do a linear scan, keeping a pointer to the previous node so that we can
       modify the pointer to the current element when we find a match. */
    stringpair_list_t **previous = & session->media_key_map;
    stringpair_list_t *rest = session->media_key_map;
    while (rest != NULL) {
        const char *item_address_pattern = rest->value->key;

        if (! strcmp (address_pattern, item_address_pattern)) {
            free (rest->value->key);
            free (rest->value->value);
            free (rest->value);
            * previous = rest->next;
            free (rest);
            return PEP_STATUS_OK;
        }

        previous = & rest->next;
        rest = rest->next;
    }

    /* If we reached the end then there was no match. */
    return PEP_KEY_NOT_FOUND;
}

/* The public function */
DYNAMIC_API PEP_STATUS config_media_keys(PEP_SESSION session,
                                         const stringpair_list_t *new_map)
{
    /* Sanity checks. */
    assert(session);
    if (! (session))
        return PEP_ILLEGAL_VALUE;
    /* A more complicated sanity check: that the new map is well formed. */
    const stringpair_list_t *rest;
    for (rest = new_map; rest != NULL; rest = rest->next)
        {
            const stringpair_t *pair = rest->value;
            /* Null pairs in a list of pairs are silly, but I can very easily
               accept them anyway. */
            if (pair == NULL)
                continue;
            const char *item_address_pattern = pair->key;
            const char *item_fpr = pair->value;
            if (item_address_pattern == NULL
                || item_fpr == NULL)
                return PEP_ILLEGAL_VALUE;
        }

    /* Keep the old map, to be restored in case of any error. */
    stringpair_list_t *old_map = session->media_key_map;

    /* Do the work: add every pair. */
    PEP_STATUS status = PEP_STATUS_OK;
    for (rest = new_map; rest != NULL; rest = rest->next) {
            const stringpair_t *pair = rest->value;
            const char *item_address_pattern = pair->key;
            const char *item_fpr = pair->value;
            status = media_key_insert(session, item_address_pattern, item_fpr);
            if (status != PEP_STATUS_OK)
                goto end;
    }

 end:
    if (status != PEP_STATUS_OK)
        session->media_key_map = old_map;
    else
        free_stringpair_list(old_map);
    return status;
}


/* Lookup.
 * ***************************************************************** */

PEP_STATUS media_key_lookup_address(PEP_SESSION session,
                                    const char *address,
                                    char **fpr_result)
{
    /* Sanity checks. */
    assert(session && address && fpr_result);
    if (! (session && address && fpr_result))
        return PEP_ILLEGAL_VALUE;

    /* Use a normalised version of the address; it is better to do this once and
       for all, out of the loop.  Notice that the address patterns being tested
       in the loop are already normalised. */
    address = normalize_address(address);

    /* Perform a trivial linear search on the list, with the first match
       winning. */
    const stringpair_list_t *rest;
    for (rest = session->media_key_map; rest != NULL; rest = rest->next) {
        const char *item_address_pattern = rest->value->key;
        const char *item_fpr = rest->value->value;
//fprintf(stderr, "* check: <%s, %s>\n", item_address_pattern, item_fpr);
        if (! pEp_fnmatch(item_address_pattern, address)) {
            *fpr_result = strdup(item_fpr);
            if (*fpr_result == NULL)
                return PEP_OUT_OF_MEMORY;
            else {
                fprintf(stderr, "<%s>: media key %s, matching pattern %s\n", address, *fpr_result, item_address_pattern);
                return PEP_STATUS_OK;
            }
        }
    }

    /* If we arrived here there is no match.  Set the output parameter as well,
       just for defensiveness' sake. */
    *fpr_result = NULL;
    return PEP_KEY_NOT_FOUND;
}


PEP_STATUS media_key_has_identity_a_media_key(PEP_SESSION session,
                                              const pEp_identity *identity,
                                              bool *has_media_key)
{
    /* Sanity checks. */
    assert(session && identity && has_media_key);
    if (! (session && identity && has_media_key))
        return PEP_ILLEGAL_VALUE;

    char *media_key = NULL;
    PEP_STATUS status
        = media_key_lookup_address(session, identity->address, & media_key);
    free(media_key);
    switch (status) {
    case PEP_STATUS_OK:
        * has_media_key = true;
        break;
    case PEP_KEY_NOT_FOUND:
        * has_media_key = false;
        status = PEP_STATUS_OK;
        break;
    default:
        /* We would not need to do anything: the status is already what we want
           to return.  However, out of defensiveness, set the Boolean result
           just in case it is used by mistake.  In doubt it is better to assume
           that an identity has *no* media key. */
        * has_media_key = false;
    }
    return status;
}


/* Media-key-related helpers for other subsystems.
 * ***************************************************************** */

PEP_STATUS identity_known_to_use_pEp(PEP_SESSION session,
                                     const pEp_identity *identity,
                                     bool *known_to_use_pEp)
{
    /* Sanity checks. */
    assert(session && identity && known_to_use_pEp);
    if (! (session && identity && known_to_use_pEp))
        return PEP_ILLEGAL_VALUE;

    bool result = false;
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *identity_copy = NULL;
    /* Easy case: an own identity. */
    if (identity->me) {
        result = true;
        goto end;
    }
        
    /* Check the database for major_ver; in case we do not know the identity
       yet, check whether the identity has a known media key: any identity with
       a media kay is also a pEp-using identity. */
    const pEp_identity *identity_to_check_and_not_free;
    status = get_identity(session, identity->address, identity->user_id,
                          & identity_copy);
    if (status != PEP_STATUS_OK)
        identity_to_check_and_not_free = identity;
    else
        identity_to_check_and_not_free = identity_copy;

    bool has_media_key;
    status = media_key_has_identity_a_media_key(session,
                                                identity_to_check_and_not_free,
                                                & has_media_key);
    if (status != PEP_STATUS_OK)
        goto end;
    if (has_media_key)
        result = true;
    else
        result = (identity_to_check_and_not_free->major_ver > 0);

 end:
    * known_to_use_pEp = result;
    free_identity (identity_copy);
    return status;
}

PEP_STATUS amend_identity_with_media_key_information(PEP_SESSION session,
                                                     pEp_identity *identity)
{
#define DUMP                                                              \
    do {                                                                  \
        fprintf(stderr, "  enc_format 0x%x %i\n",                         \
                (int) identity->enc_format, (int) identity->enc_format);  \
        fprintf(stderr, "  comm_type  0x%x %i\n",                         \
                (int) identity->comm_type, (int) identity->comm_type);    \
        fprintf(stderr, "  version    %i.%i\n",                           \
                (int) identity->major_ver, (int) identity->minor_ver);    \
    } while (false)

    /* Sanity checks. */
    assert(session && identity);
    if (! (session && identity))
        return PEP_ILLEGAL_VALUE;

    /* Check whether the identity has a media key: */
    bool has_media_key;
    PEP_STATUS status
        = media_key_has_identity_a_media_key(session, identity, & has_media_key);

    /* On error relay the error and do nothing else. */
    if (status != PEP_STATUS_OK)
        return status;

    /* If there is no media key, do nothing. */
    if (! has_media_key)
        return PEP_STATUS_OK;

    /* If we arrived here there is a media key.  Amend the identity so that it
       is recognised as using a recent pEp version. */
    fprintf(stderr, "%s <%s>: amending because of a media key...\n", identity->username, identity->address); \
    DUMP;
    if (identity->enc_format == PEP_enc_auto
        || identity->enc_format < PEP_enc_PEP)
        identity->enc_format = PEP_enc_PEP;
#define AMEND_COMM_TYPE(the_comm_type)                      \
    do {                                                    \
        PEP_comm_type _the_comm_type = (the_comm_type);     \
        if (identity->comm_type == PEP_ct_unknown           \
            || identity->comm_type == PEP_ct_no_encryption  \
            || identity->comm_type < _the_comm_type)        \
            identity->comm_type = _the_comm_type;           \
    } while (false)
    AMEND_COMM_TYPE(media_key_comm_type);
    if (identity->major_ver < 2
        || (identity->major_ver == 2 && identity->minor_ver < 1)) {
        identity->major_ver = 2;
        identity->minor_ver = 1;
    }
    fprintf(stderr, "  ->\n");
    DUMP;
    return PEP_STATUS_OK;
}


/* Policy.
 * ***************************************************************** */

const PEP_rating media_key_message_rating
  = PEP_rating_unreliable;
//  = PEP_rating_under_attack; // for tests, of course.

/* This is useful for determining the colour of an outgoing message. */
const PEP_comm_type media_key_comm_type
  = PEP_ct_unconfirmed_encryption;

const PEP_enc_format media_key_enc_format
  = PEP_enc_PEP;

/* A simple helper for media_key_is_there_a_media_key_in . */
static bool media_key_is_a_media_key(const stringpair_list_t *map,
                                     const char *fpr)
{
    const stringpair_list_t *rest;
    for (rest = map; rest != NULL; rest = rest->next) {
        const char *item_fpr = rest->value->value;
        //fprintf(stderr, "Comparing %s against the known media key %s\n", fpr, item_fpr);
        if (fprs_equal(fpr, item_fpr))
            return true;
    }
    return false;
}

PEP_STATUS media_key_is_there_a_media_key_in(PEP_SESSION session,
                                             const stringlist_t *keylist,
                                             bool *found)
{
    /* Sanity checks. */
    assert(session && found);
    if (! (session && found))
        return PEP_ILLEGAL_VALUE;

    /* Check every element. */
    const stringpair_list_t *map = session->media_key_map;
    const stringlist_t *rest;
    * found = false;
    for (rest = keylist; rest != NULL; rest = rest->next) {
        const char *fpr = rest->value;
        //fprintf(stderr, "Checking if %s is a known media key\n", fpr);
        if (media_key_is_a_media_key(map, fpr)) {
            * found = true;
            break;
        }
    }
    return PEP_STATUS_OK;
}

/* A helper for media_key_for_outgoing_message.  fpr_inout is an inout
   parameter: if on input it was NULL it will be updated with success to be a
   media key, in case the identity has a valid media key; if on input fpr_input
   was already a media key then the function does not change it as long as it
   is valid for the given identity as well; in case the identity requires a
   different media key or no media key the function returns failure. */
static PEP_STATUS media_key_add_address(PEP_SESSION session,
                                        const pEp_identity *identity,
                                        char **fpr_inout)
{
    char *fpr_for_identity = NULL;
    PEP_STATUS status = media_key_lookup_address(session, identity->address,
                                                 & fpr_for_identity);
    if (status != PEP_STATUS_OK)
        goto end;

    /* If we arrived here then key was found.  We keep it only if it is either
       equal to the inout key, or the inout key was NULL. */
    if (* fpr_inout != NULL && ! fprs_equal(* fpr_inout, fpr_for_identity)) {
        free(fpr_for_identity);
        fpr_for_identity = NULL;
        status = PEP_KEY_NOT_FOUND;
    }

 end:
    /* Set the inout parameter to the result, be it NULL or otherwise. */
    free(* fpr_inout);
    * fpr_inout = fpr_for_identity;
    return status;
}

/* The obvious extension of media_key_add_address to a list of identities. */
static PEP_STATUS media_key_add_addresses(PEP_SESSION session,
                                          const identity_list *identities,
                                          char **fpr_inout)
{
    PEP_STATUS status = PEP_STATUS_OK;
    const identity_list *rest;
    for (rest = identities;
         rest != NULL && status == PEP_STATUS_OK;
         rest = rest->next)
        status = media_key_add_address(session, rest->ident, fpr_inout);
    return status;
}

PEP_STATUS media_key_for_outgoing_message(PEP_SESSION session,
                                          const message *msg,
                                          char **fpr_result)
{
    /* Sanity checks. */
    assert(session && msg);
    if (! (session && msg))
        return PEP_ILLEGAL_VALUE;
    if (msg->dir != PEP_dir_outgoing)
        return PEP_ILLEGAL_VALUE;

    /* Special case: if there is any Bcc recipient then we can use no media
       key. */
    PEP_STATUS status = PEP_STATUS_OK;
    char *candidate_key = NULL;
    if (msg->bcc != NULL) {
        status = PEP_KEY_NOT_FOUND;
        goto end;
    }

    /* Check that we can use the same key for every field: */
#define ADD_IDENTITIES(identities)                              \
    do {                                                        \
        const identity_list *_identities = (identities);        \
        status = media_key_add_addresses(session, _identities,  \
                                         &candidate_key);       \
        if (status != PEP_STATUS_OK)                            \
            goto end;                                           \
    } while (false)
    ADD_IDENTITIES(msg->to);
    ADD_IDENTITIES(msg->cc);

 end:
    if (fpr_result != NULL)
        * fpr_result = candidate_key;
    fprintf(stderr, "* The message %s has media key %s\n", (msg->shortmsg ? msg->shortmsg : "(no subject)"), (candidate_key ? candidate_key : "(no key)"));
    return status;
}
