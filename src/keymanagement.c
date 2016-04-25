#include "platform.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "pEp_internal.h"
#include "keymanagement.h"

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
#endif

#define KEY_EXPIRE_DELTA (60 * 60 * 24 * 365)

#ifndef MIN
#define MIN(A, B) ((B) > (A) ? (A) : (B))
#endif
#ifndef MAX
#define MAX(A, B) ((B) > (A) ? (B) : (A))
#endif

// Space tolerant and case insensitive fingerprint string compare
static int _same_fpr(
        const char* fpra,
        size_t fpras,
        const char* fprb,
        size_t fprbs
    )
{
    size_t ai = 0;
    size_t bi = 0;
    
    do
    {
        if(fpra[ai] == 0 || fprb[bi] == 0)
        {
            return 0;
        }
        else if(fpra[ai] == ' ')
        {
            ai++;
        }
        else if(fprb[bi] == ' ')
        {
            bi++;
        }
        else if(toupper(fpra[ai]) == toupper(fprb[bi]))
        {
            ai++;
            bi++;
        }
        else
        {
            return 0;
        }
    }
    while(ai < fpras && bi < fprbs);
    
    return ai == fpras && bi == fprbs;
}

#ifndef NDEBUG

static void _debug_log_identity_address_fpr(PEP_SESSION session,
                                            const char* title,
                                            const char* entity,
                                            pEp_identity *identity)
{
    size_t dbgmsg_size = identity->address_size + identity->fpr_size + 4;
    char* dbgmsg = calloc(1, dbgmsg_size);
    if (dbgmsg)
    {
        snprintf(dbgmsg, dbgmsg_size, "%s (%s)",
                 identity->address,identity->fpr);
        DEBUG_LOG(title, entity, dbgmsg);
    }
}

#define DEBUG_LOG_IDENTITY(TITLE, ENTITY, IDENTITY) \
    _debug_log_identity_address_fpr(session, (TITLE), (ENTITY), (IDENTITY));

#else

#define DEBUG_LOG_IDENTITY(TITLE, ENTITY, IDENTITY)

#endif


static bool _apply_comm_type(PEP_comm_type *dst, PEP_comm_type target_comm_type)
{
    switch(target_comm_type)
    {
        
        case PEP_ct_unknown:
            return false;
            
        case PEP_ct_no_encryption:
        case PEP_ct_unconfirmed_encryption:
        case PEP_ct_to_be_checked:
        case PEP_ct_strong_but_unconfirmed:
        case PEP_ct_unconfirmed_enc_anon:
            
            // ignore generic types
            return false;
            
        case PEP_ct_confirmed:
        case PEP_ct_confirmed_encryption:
            
            // case of trust_personal_key
            // applies only to unconfirmed encryption
            if (*dst > PEP_ct_unconfirmed_encryption)
            {
                *dst |= PEP_ct_confirmed;
                return true;
            }
            return false;
            
        case PEP_ct_to_be_checked_confirmed:
        case PEP_ct_strong_encryption:
        case PEP_ct_confirmed_enc_anon:
            
            // ignore other generic comm_types
            return false;
            
        case PEP_ct_pEp:
            
            // case of own identity
            if (*dst > PEP_ct_unconfirmed_encryption)
            {
                *dst = PEP_ct_pEp;
                return true;
            }
            return false;
            
        default:
            
            if ((target_comm_type & ~(*dst)) == PEP_ct_confirmed)
            {
                // Again case of trust_personal_key
                // but at second confrontation
                *dst = target_comm_type;
                return true;
            }
            return false;
    }
}

// confront_identity() - confront identity to what pEpEngine already knows.
//
//  parameters:
//      session (in)                session handle
//		identity (inout)            pointer to pEp_identity structure
//		target_comm_type (in)       comm_type to be applied to identity
//      outstanding_changes (OUT)   identity contains changes to be stored
//
//  This function modifies the given identity struct; the struct remains in
//  the ownership of the caller.
//
//  If identity->user_id is not provided, then a default user_id is created,
//  based on address.
//
//  When wanted_com_type is given, it is applied to identity if not in
//  contradiction with current state.
//
//  identity->me is taken in account, and may be reset if not applicable.
//  Key's ownership (status of being created by pEp) can be forced by
//  setting target_comm_type to PEP_ct_pEp, and providing target fpr.
//
//  Identity is not stored in database. This is caller's responsibility
//  to store identities with outstanding_changes.
//  Calling confront_identity doesn't modify pEpEngine's internal state,
//  and is not blocking.
//
//  Caller MUST NOT store modified identity if either :
//    - outstanding_changes is false
//    - identity->comm_type is PEP_ct_unknown
//    - returned value different from PEP_STATUS_OK
//
//  Caller SHOULD store modified identity if both :
//    - outstanding_changes is true
//    - identity->comm_type is greater PEP_ct_unknown
//    - returned value is PEP_STATUS_OK
//
//  Confront_identity behavior should be consistent across successive
//  calls on the same identity, provided that :
//         - initial call did set outstanding_changes to true,
//         - engine state is unchanged between calls.
//

static PEP_STATUS confront_identity(
        PEP_SESSION session,
        pEp_identity * identity,
        PEP_comm_type target_comm_type,
        bool *outstanding_changes
    )
{
    pEp_identity *stored_identity = NULL;
    PEP_STATUS status;
    int _no_fpr = EMPTYSTR(identity->fpr);
    int _no_user_id = EMPTYSTR(identity->user_id);

    if (_no_user_id)
    {
        if (identity->me)
        {
            // App MUST provide unique user_id
            // for each local account
            return PEP_ILLEGAL_VALUE;
        }
        
        free(identity->user_id);

        status = get_best_user(session,
                              identity->address,
                              &identity->user_id);

        // Default user_id, aka Virtual user_id
        if (status == PEP_CANNOT_FIND_IDENTITY)
        {
            identity->user_id = calloc(1, identity->address_size + 5);
            snprintf(identity->user_id, identity->address_size + 5,
                     "TOFU_%s", identity->address);
        }
        else if (status != PEP_STATUS_OK)
        {
            return status;
        }
    }
    
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);
    
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;
    
    *outstanding_changes = false;
    
    if (stored_identity)
    {
        PEP_comm_type _stored_comm_type_key;
        status = get_key_rating(session,
                                stored_identity->fpr,
                                &_stored_comm_type_key);
        
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
        {
            free_identity(stored_identity);
            return PEP_OUT_OF_MEMORY;
        }

        if (EMPTYSTR(identity->username) &&
            !EMPTYSTR(stored_identity->username))
        {
            free(identity->username);
            identity->username = strndup(stored_identity->username,
                                         stored_identity->username_size);
            assert(identity->username);
            if (identity->username == NULL)
            {
                free_identity(stored_identity);
                return PEP_OUT_OF_MEMORY;
            }
            identity->username_size = stored_identity->username_size;
        }
        else
        {
            // See what username is given, if not the same as stored.
            if (!EMPTYSTR(identity->username) &&
                (EMPTYSTR(stored_identity->username) ||
                 stored_identity->username_size != identity->username_size ||
                 strncmp(stored_identity->username,
                         identity->username,
                         identity->username_size) != 0))
            {
                // If no user ID was given, this is just information
                *outstanding_changes = !_no_user_id;
            }
        }

        // Fpr is not given or is equivalent to stored
        if (_no_fpr ||
            _same_fpr(identity->fpr,
                      identity->fpr_size,
                      stored_identity->fpr,
                      stored_identity->fpr_size))
        {
            
            if (_stored_comm_type_key < PEP_ct_unconfirmed_encryption)
            {
                // Id key's rating bad, smash ident's comm_type
                identity->comm_type = _stored_comm_type_key;
 
                // Lose ownership if stored identity is not our own
                identity->me &= stored_identity->me;
            }
            else
            {
                if (_no_fpr ||
                    target_comm_type == PEP_ct_unknown ||
                    stored_identity->comm_type < PEP_ct_unconfirmed_encryption)
                {
                    // Take stored comm_type as-is when no fpr given,
                    // or if bad comm_type or when no target given
                    identity->comm_type = stored_identity->comm_type;
                    
                    // Lose ownership if stored identity is not our own
                    identity->me &= stored_identity->me;
                }
                else
                {
                    // XXX return value -> outstanding_changes
                    // Otherwise, accept wanted comm_type
                    _apply_comm_type(&identity->comm_type, target_comm_type);
                }
                
                if (identity->comm_type == PEP_ct_unknown)
                {
                    // If still unset at that point, take key's comm_type
                    identity->comm_type = _stored_comm_type_key;
                    
                    // If no user ID was given, this is just information
                    *outstanding_changes = !_no_user_id;
                }
            }
            
            if(_no_fpr)
            {
                // Copy fpr only in case it wasn't given
                free(identity->fpr);
                identity->fpr = strndup(stored_identity->fpr,
                                        stored_identity->fpr_size);
                assert(identity->fpr);
                if (identity->fpr == NULL)
                {
                    free_identity(stored_identity);
                    return PEP_OUT_OF_MEMORY;
                }
                identity->fpr_size = stored_identity->fpr_size;
            }
        }
        
        // Fpr given but different from stored
        else if (!_no_fpr &&
                 !_same_fpr(identity->fpr,
                            identity->fpr_size,
                            stored_identity->fpr,
                            stored_identity->fpr_size))
        {
            
            // This case can happen when re-confronting queued identity,
            // after execution of other conflicting operations on same identity
            // that would have been queued earlier.
            // Confrontation should result in selecting the most appropriate key
            
            PEP_comm_type _given_key_comm_type;
            status = get_key_rating(session,
                                    stored_identity->fpr,
                                    &_given_key_comm_type);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status != PEP_STATUS_OK)
            {
                free_identity(stored_identity);
                return status;
            }
            
            // Ensure that given fpr match a key with corresponding address
            // TODO : make a dedicated crypto call for that purpose

            stringlist_t *keylist = NULL;
            stringlist_t *_keylist;
            
            status = find_keys(session, identity->address, &keylist);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY)
            {
                free_identity(stored_identity);
                return PEP_OUT_OF_MEMORY;
            }

            for (_keylist = keylist;
                 _keylist && _keylist->value;
                 _keylist = _keylist->next)
            {
                if (_same_fpr(identity->fpr,
                              identity->fpr_size,
                              _keylist->value,
                              strlen(_keylist->value)))
                {
                    break;
                }
            }

            assert(_keylist != NULL);
            if (_keylist == NULL)
            {
                free_stringlist(keylist);
                free_identity(stored_identity);
                return PEP_KEY_HAS_AMBIG_NAME;
            }

            free_stringlist(keylist);

            PEP_comm_type _least_comm_type = PEP_ct_unknown;
            
            status = least_trust(session, identity->fpr, &_least_comm_type);
            if (status != PEP_STATUS_OK &&
                status != PEP_CANNOT_FIND_IDENTITY)
            {
                free_identity(stored_identity);
                return status;
            }
            
            if (
                // Bad key ?
                _given_key_comm_type < PEP_ct_unconfirmed_encryption ||
                
                // no target and proposed key comm_type weaker than pre-existing
                (target_comm_type == PEP_ct_unknown &&
                 _given_key_comm_type <= stored_identity->comm_type) ||
                
                // key is already known, and has bad press
                (_least_comm_type != PEP_ct_unknown &&
                 _least_comm_type < PEP_ct_unconfirmed_encryption) ||
                
                // target comm_type given but lower than pre-existing
                (target_comm_type != PEP_ct_unknown &&
                 target_comm_type < stored_identity->comm_type) ||
                
                // wanted comm_type greater than available trust
                // (key reset trust needed)
                (_least_comm_type != PEP_ct_unknown &&
                 target_comm_type != PEP_ct_unknown &&
                 target_comm_type > _least_comm_type))
            {
                // ignore.
                identity->comm_type = PEP_ct_unknown;
            }
            else
            {
                bool _ct_updated = false;
                if(target_comm_type != PEP_ct_unknown)
                {
                    _ct_updated = _apply_comm_type(&identity->comm_type,
                                                   target_comm_type);
                }
                else
                {
                    identity->comm_type = _given_key_comm_type;
                    _ct_updated = true;
                }

                if (identity->me)
                {
                    int created = 0;

                    status = get_pgp_keypair_created(session,
                                                     identity->fpr,
                                                     &created);
                    
                    assert(status == PEP_STATUS_OK);
                    if (status != PEP_STATUS_OK)
                    {
                        free_identity(stored_identity);
                        return status;
                    }
                    
                    // ownership preserved only if new keypair really our own
                    if (created)
                    {
                        // If no user ID was given, this is just information
                        *outstanding_changes = !_no_user_id && _ct_updated;
                    }
                    else
                    {
                        identity->me = false;
                    }
                }
                else
                {
                    // If no user ID was given, this is just information
                    *outstanding_changes = !_no_user_id && _ct_updated;
                }
            }
        }

        if (identity->lang[0] == 0)
        {
            identity->lang[0] = stored_identity->lang[0];
            identity->lang[1] = stored_identity->lang[1];
            identity->lang[2] = 0;
        }
        
        free_identity(stored_identity);
    }
    else /* stored_identity == NULL */
    {
        stringlist_t *keylist;
        identity->comm_type = PEP_ct_unknown;
        
        status = find_keys(session, identity->address, &keylist);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;
        
        stringlist_t *_keylist;

        if (!_no_fpr)
        {
            // Find pgp key matching both address and given fpr
            for (_keylist = keylist;
                 _keylist && _keylist->value;
                 _keylist = _keylist->next)
            {
                if (_same_fpr(identity->fpr,
                              identity->fpr_size,
                              _keylist->value,
                              strlen(_keylist->value)))
                {
                    if (identity->me)
                    {
                        // New own identity is accepted if
                        // key is already known as own
                        int created = 0;
                        status = get_pgp_keypair_created(session,
                                                         identity->fpr,
                                                         &created);
                        
                        assert(status == PEP_STATUS_OK);
                        if (status != PEP_STATUS_OK)
                        {
                            free_stringlist(keylist);
                            return status;
                        }
                        
                        // Or, when a key wasn't created, it is possible to
                        // force it if target_com_type is PEP_ct_pEp

                        if (created ||
                            (!created && target_comm_type == PEP_ct_pEp))
                        {
                            break;
                        }
                        else
                        {
                            free_stringlist(keylist);
                            return PEP_KEY_NOT_FOUND;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
            
            assert(_keylist != NULL);
            if (_keylist == NULL)
            {
                free_stringlist(keylist);
                return PEP_KEY_HAS_AMBIG_NAME;
            }
            
            PEP_comm_type _least_comm_type = PEP_ct_unknown;

            status = least_trust(session, identity->fpr, &_least_comm_type);
            if (status != PEP_STATUS_OK &&
                status != PEP_CANNOT_FIND_IDENTITY)
            {
                free_stringlist(keylist);
                return status;
            }
            
            if(_least_comm_type == PEP_ct_unknown ||
               _least_comm_type >= PEP_ct_unconfirmed_encryption)
            {
                PEP_comm_type _comm_type_key;
                
                status = get_key_rating(session,
                                        identity->fpr,
                                        &_comm_type_key);
                
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY)
                {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }

                identity->comm_type = _comm_type_key;
                
                *outstanding_changes = true;
            }
            else
            {
                identity->comm_type = _least_comm_type;
            }
        }
        else /* _no_fpr */
        {
            char *_fpr = NULL;
            bool _elected_outstanding = false;
            PEP_comm_type _elected_comm_type = PEP_ct_unknown;

            free(identity->fpr);
            identity->fpr = NULL;
            
            // Loop over address matching keylist to elect the best key
            for (_keylist = keylist;
                 _keylist && _keylist->value;
                 _keylist = _keylist->next)
            {
                PEP_comm_type _candidate_comm_type = PEP_ct_unknown;

                status = least_trust(session,
                                     _keylist->value,
                                     &_candidate_comm_type);
                
                if (status != PEP_STATUS_OK &&
                    status != PEP_CANNOT_FIND_IDENTITY)
                {
                    free_stringlist(keylist);
                    return status;
                }
                
                // Include unknown keys, exclude key with known problems
                if(_candidate_comm_type == PEP_ct_unknown ||
                   _candidate_comm_type >= PEP_ct_unconfirmed_encryption)
                {
                    status = get_key_rating(session,
                                            _keylist->value,
                                            &_candidate_comm_type);
                    
                    assert(status != PEP_OUT_OF_MEMORY);
                    if (status == PEP_OUT_OF_MEMORY)
                    {
                        free_stringlist(keylist);
                        return PEP_OUT_OF_MEMORY;
                    }
                    
                    // Filter-out keys that are not created if we are searchin
                    // for a key for own identity.
                    if (identity->me)
                    {
                        int created = 0;
                        status = get_pgp_keypair_created(session,
                                                         _keylist->value,
                                                         &created);
                        
                        assert(status == PEP_STATUS_OK);
                        if (status != PEP_STATUS_OK)
                        {
                            free_stringlist(keylist);
                            return status;
                        }
                        
                        if (!created)
                        {
                            break;
                        }
                    }
                }

                // Elect if the best.
                if (_candidate_comm_type > identity->comm_type)
                {
                    _elected_comm_type = _candidate_comm_type;
                    _fpr = _keylist->value;

                    _elected_outstanding =
                        _candidate_comm_type >= PEP_ct_unconfirmed_encryption;
                }
            }

            if (_fpr && _elected_comm_type >= target_comm_type)
            {
                identity->fpr = strdup(_fpr);
                if (identity->fpr == NULL) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }
                identity->fpr_size = strlen(identity->fpr);
                
                identity->comm_type = _elected_comm_type;
                
                *outstanding_changes = _elected_outstanding;
            }
            else
            {
                // No satisfying key found, need a new one.
                
                // In that case comm_type is set to target,
                // but fpr is left empty.
                identity->comm_type = target_comm_type;
            }
            free_stringlist(keylist);
        }
    }

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status;
    bool outstanding_changes = false;

    assert(session);
    assert(session->examine_identity);
    assert(identity);
    assert(!EMPTYSTR(identity->address));
    assert(!identity->me);

    if (!(session &&
          session->examine_identity &&
          identity &&
          !EMPTYSTR(identity->address) &&
          !identity->me))
    {
        return PEP_ILLEGAL_VALUE;
    }

    status = confront_identity(session,
                               identity,
                               PEP_ct_unknown, // comm_type is read_only
                               &outstanding_changes);
        
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;
    
    if (identity->comm_type != PEP_ct_unknown &&
        outstanding_changes)
    {
        // This causes identity to be re-confronted and stored
        // asynchronously, by keymanagement thread.
        
        if (session->examine_identity(identity,
                                      session->examine_management))
        {
            return PEP_OUT_OF_MEMORY;
        }
    }

    if (identity->comm_type != PEP_ct_compromized &&
        identity->comm_type < PEP_ct_strong_but_unconfirmed)
    {
        if (session->examine_identity)
        {
            // Pass only address to keymanagement thread
            // to trigger keyserver request
            pEp_identity *tmp_identity = new_identity(identity->address,
                                                      NULL, NULL, NULL);
            if (session->examine_identity(tmp_identity,
                                          session->examine_management))
            {
                return PEP_OUT_OF_MEMORY;
            }
            free_identity(tmp_identity);
        }
    }

    return PEP_STATUS_OK;
}

// This is meant to be called only from key management thread
// no concurrency is allowed here.
static PEP_STATUS ensure_own_key(PEP_SESSION session, pEp_identity * identity)
{
    PEP_STATUS status;
    bool revoked = false;
    
    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));
    assert(!EMPTYSTR(identity->user_id));
    assert(identity->me);
    
    DEBUG_LOG("update_own_key", "debug", identity->address);
    
    if (!(session && identity &&
          identity->address &&
          identity->user_id &&
          identity->me))
    {
        return PEP_ILLEGAL_VALUE;
    }
    
    if (!EMPTYSTR(identity->fpr))
    {
        status = key_revoked(session, identity->fpr, &revoked);
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK)
        {
            return status;
        }
    }

    if (EMPTYSTR(identity->fpr) || revoked)
    {
        DEBUG_LOG("generating key pair", "debug", identity->address);
        
        free(identity->fpr);
        identity->fpr = NULL;
        
        status = generate_keypair(session, identity);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status != PEP_STATUS_OK)
        {
            char buf[11];
            snprintf(buf, 11, "%d", status);
            DEBUG_LOG("generating key pair failed", "debug", buf);
            return status;
        }
        
        assert(!EMPTYSTR(identity->fpr));
        if (EMPTYSTR(identity->fpr))
        {
            return PEP_UNKNOWN_ERROR;
        }
    }
    else
    {
        bool expired;
        status = key_expired(session, identity->fpr, &expired);
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK) {
            return status;
        }
        
        if (status == PEP_STATUS_OK && expired) {
            timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
            renew_key(session, identity->fpr, ts);
            free_timestamp(ts);
        }
    }
    
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    PEP_STATUS status;
    bool outstanding_changes = false;

    assert(session);
    assert(session->examine_identity);
    assert(identity);
    assert(!EMPTYSTR(identity->address));
    assert(!EMPTYSTR(identity->user_id));

    if (!(session &&
          session->examine_identity &&
          identity &&
          identity->address &&
          identity->user_id))
    {
        return PEP_ILLEGAL_VALUE;
    }

    identity->me = true;

    DEBUG_LOG("myself", "debug", identity->address);
    
    status = confront_identity(session,
                               identity,
                               PEP_ct_pEp,
                               &outstanding_changes);
    
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;
    
    if (// Case something was given or found
        (identity->me &&
         identity->comm_type != PEP_ct_unknown &&
         !EMPTYSTR(identity->fpr) &&
         outstanding_changes) ||
        
        // Case there is nothing else than an address
        (identity->me &&
         identity->comm_type == PEP_ct_pEp &&
         EMPTYSTR(identity->fpr)))
    {
        if (session->examine_identity(identity,
                                      session->examine_management))
        {
            return PEP_OUT_OF_MEMORY;
        }
        return PEP_STATUS_OK;
    }
    
    return PEP_UNKNOWN_ERROR;
}

DYNAMIC_API PEP_STATUS register_examine_function(
        PEP_SESSION session, 
        examine_identity_t examine_identity,
        void *management
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    session->examine_management = management;
    session->examine_identity = examine_identity;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS do_keymanagement(
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    )
{
    PEP_SESSION session;
    pEp_identity *identity;
    pEp_identity *processed_identity = NULL;
    PEP_STATUS status;
    bool allow_keyserver_lookup = false;

    assert(retrieve_next_identity);
    assert(management);

    if (!retrieve_next_identity || !management)
        return PEP_ILLEGAL_VALUE;

    status = init(&session);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;

    log_event(session, "keymanagement thread started", "pEp engine", NULL, NULL);

    while ((identity = retrieve_next_identity(processed_identity,
                                              management,
                                              &allow_keyserver_lookup)))
    {
        DEBUG_LOG("do_keymanagement", "retrieve_next_identity", NULL);
        bool outstanding_changes = false;

        if(processed_identity)
        {
            free_identity(processed_identity);
            processed_identity = NULL;
        }
        
        if (!EMPTYSTR(identity->address) &&
            identity->me &&
            !EMPTYSTR(identity->fpr) &&
            identity->comm_type == PEP_ct_mistrusted &&
            !EMPTYSTR(identity->user_id))
        {
            DEBUG_LOG("do_keymanagement", "revoking", identity->fpr);

            // Case of own key to be revoked
            status = revoke_key(session, identity->fpr, NULL);
            
            if (status == PEP_STATUS_OK)
            {
                // This changes the identity to match next if statement
                identity->comm_type = PEP_ct_pEp;
            }
        }
        
        if (!EMPTYSTR(identity->address) &&
            identity->me &&
            identity->comm_type == PEP_ct_pEp &&
            !EMPTYSTR(identity->user_id))
        {
            // Own identity issued by a call to Myself()
            // or above revoked identity
            
            DEBUG_LOG("do_keymanagement", "confront_identity (me)",
                      identity->address);
            
            status = confront_identity(session,
                                       identity,
                                       PEP_ct_pEp,
                                       &outstanding_changes);
        
            if (// Case something was found
                (identity->me &&
                 identity->comm_type != PEP_ct_unknown &&
                 !EMPTYSTR(identity->fpr) &&
                 outstanding_changes) ||
                
                // Case there is nothing else than an address
                (identity->me &&
                 identity->comm_type == PEP_ct_pEp &&
                 EMPTYSTR(identity->fpr)))
            {
                // TODO : move key-gen op to a different thread
                //        keygen would then re-enqueue identity once
                //        key would have been generated.
                //        This would avoid blocking key management while
                //        generating key.
                
                DEBUG_LOG("do_keymanagement", "ensure_own_key",
                          identity->address);
                
                status = ensure_own_key(session, identity);
                if(status == PEP_STATUS_OK &&
                   identity->me)
                {
                    identity->comm_type = PEP_ct_pEp;

                    DEBUG_LOG_IDENTITY("do_keymanagement",
                                       "set_identity",
                                       identity);
                    
                    status = set_identity(session, identity);
                }
            }
        }
        else if (!EMPTYSTR(identity->address) &&
                 !identity->me &&
                 !EMPTYSTR(identity->fpr) &&
                 identity->comm_type != PEP_ct_unknown &&
                 !EMPTYSTR(identity->user_id))
        {

            // Identity with some outstanding changes. Could come from
            //  update_identity or trust_personal_key
            
            DEBUG_LOG("do_keymanagement", "confront_identity",
                      identity->address);
            
            status = confront_identity(session,
                                       identity,
                                       PEP_ct_unknown,
                                       &outstanding_changes);

            if(status == PEP_STATUS_OK &&
               identity->comm_type != PEP_ct_unknown &&
               outstanding_changes)
            {
                DEBUG_LOG_IDENTITY("do_keymanagement", "set_identity",
                                   identity);
                
                status = set_identity(session, identity);
            }
        }
        else if (EMPTYSTR(identity->address) &&
                 !identity->me &&
                 !EMPTYSTR(identity->fpr) &&
                 EMPTYSTR(identity->user_id) &&
                 EMPTYSTR(identity->username))
        {
            // Order to force or reset trust.
            // For key_reset_trust and key_mistrusted
            
            DEBUG_LOG("do_keymanagement", "(un)forcing trust",
                      identity->fpr);
            

            if (identity->comm_type == PEP_ct_mistrusted)
            {
                
                // Mistrust Key
                
                DEBUG_LOG("do_keymanagement", "set_fpr_trust PEP_ct_mistrusted",
                          identity->fpr);

                // XXX : shall we refuse to refuse to
                //       set mistrust on created identities ?
                
                // Apply mistrust
                status = set_fpr_trust(session,
                                       identity->fpr,
                                       PEP_ct_mistrusted);
            }
            else if (identity->comm_type == PEP_ct_unknown)
            {
                // Reset trust
                
                PEP_comm_type _least_comm_type = PEP_ct_unknown;
                
                status = least_trust(session, identity->fpr, &_least_comm_type);
                
                if (status == PEP_STATUS_OK ||
                    status == PEP_CANNOT_FIND_IDENTITY)
                {
                    // refuse to reset compromized key
                    if(_least_comm_type != PEP_ct_compromized)
                    {
                        // Reset trust for an fpr consist in setting
                        // original key comm_type as new trust
                        
                        PEP_comm_type _comm_type_key;
                        
                        DEBUG_LOG("do_keymanagement",
                                  "get_key_rating",
                                  identity->fpr);
                        
                        status = get_key_rating(session,
                                                identity->fpr,
                                                &_comm_type_key);
                        
                        // XXX : shall we reset to PEP_ct_pEp for
                        //       created identities ?
                        
                        if (status == PEP_STATUS_OK)
                        {
                            DEBUG_LOG("do_keymanagement",
                                      "set_fpr_trust (key's comm_type)",
                                      identity->fpr);
                            
                            // Apply key's comm_type as trust
                            status = set_fpr_trust(session,
                                                   identity->fpr,
                                                   _comm_type_key);
                        }
                    }
                }
            }
            else
            {
                DEBUG_LOG("do_keymanagement",
                          "BUG : trying to force trust with "
                           "inappropriate value !",
                          NULL);
                
                assert(true);
            }
        }
        else if (!EMPTYSTR(identity->address) &&
                 EMPTYSTR(identity->fpr) &&
                 identity->comm_type == PEP_ct_unknown &&
                 EMPTYSTR(identity->user_id) &&
                 EMPTYSTR(identity->username))
        {
            // Key server lookup
            
            if (allow_keyserver_lookup)
            {
                DEBUG_LOG("do_keymanagement", "recv_key",
                          identity->address);

                // Key server requests only has address set.
                status = recv_key(session, identity->address);
            }
        }

        assert(status != PEP_OUT_OF_MEMORY);
        if(status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;

        processed_identity = identity;
        allow_keyserver_lookup = false;
    }

    if(processed_identity)
    {
        free_identity(processed_identity);
        processed_identity = NULL;
    }
    
    log_event(session, "keymanagement thread shutdown", "pEp engine", NULL, NULL);

    release(session);
    return PEP_STATUS_OK;
}

static PEP_STATUS _key_force_trust_async(
       PEP_SESSION session,
       pEp_identity *ident,
       PEP_comm_type order
   )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->fpr));
    
    if (!(session && ident && ident->fpr))
    {
        return PEP_ILLEGAL_VALUE;
    }
    
    if (session->examine_identity)
    {
        // Pass only fpr
        pEp_identity *tmp_identity = new_identity(NULL, ident->fpr,
                                                  NULL, NULL);
        
        // Management thread forces according to given order.
        tmp_identity->comm_type = order;
        
        if (session->examine_identity(tmp_identity,
                                      session->examine_management))
        {
            return PEP_OUT_OF_MEMORY;
        }
        free_identity(tmp_identity);
    }
    else
    {
        return PEP_NO_MANAGEMENT_THREAD;
    }
    
    return status;
}




DYNAMIC_API PEP_STATUS key_mistrusted(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    return _key_force_trust_async(session, ident, PEP_ct_mistrusted);
}

DYNAMIC_API PEP_STATUS key_reset_trust(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    return _key_force_trust_async(session, ident, PEP_ct_mistrusted);
}

DYNAMIC_API PEP_STATUS trust_personal_key(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    bool outstanding_changes = false;

    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));
    assert(!EMPTYSTR(ident->fpr));
    assert(!ident->me);

    if (!(session &&
          ident &&
          !EMPTYSTR(ident->address) &&
          !EMPTYSTR(ident->user_id) &&
          !EMPTYSTR(ident->fpr) &&
          !ident->me))
    {
        return PEP_ILLEGAL_VALUE;
    }

    status = confront_identity(session,
                               ident,
                               PEP_ct_confirmed,
                               &outstanding_changes);
    
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type > PEP_ct_strong_but_unconfirmed &&
        outstanding_changes)
    {
        ident->comm_type |= PEP_ct_confirmed;
        
        if (session->examine_identity)
        {
            if (session->examine_identity(ident,
                                          session->examine_management))
            {
                return PEP_OUT_OF_MEMORY;
            }
        }
        else
        {
            // FIXME : having no keymanagement thread
            // shouldn't be allowed.
            
            status = set_identity(session, ident);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                return status;
            }
        }
    }
    else {
        // MISSING: S/MIME has to be handled depending on trusted CAs
        status = PEP_CANNOT_SET_TRUST;
    }

    return status;
}

