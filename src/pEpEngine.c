/** @file pEpEngine.c 
 * @brief implementation of the pEp Engine API
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "cryptotech.h"
#include "transport.h"
#include "KeySync_fsm.h"
#include "engine_sql.h"

#include <time.h>
#include <stdlib.h>

#ifdef _PEP_SQLITE_DEBUG
#include <sqlite3.h>
#endif

static volatile int init_count = -1;

DYNAMIC_API PEP_STATUS init(
        PEP_SESSION *session,
        messageToSend_t messageToSend,
        inject_sync_event_t inject_sync_event,
        ensure_passphrase_t ensure_passphrase
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    bool in_first = false;

    assert(sqlite3_threadsafe());
    if (!sqlite3_threadsafe())
        return PEP_INIT_SQLITE3_WITHOUT_MUTEX;

    // a little race condition - but still a race condition
    // mitigated by calling caveat (see documentation)

    // this increment is made atomic IN THE ADAPTERS by
    // guarding the call to init with the appropriate mutex.
    int _count = ++init_count;
    if (_count == 0)
        in_first = true;
    
    // Race condition mitigated by calling caveat starts here :
    // If another call to init() preempts right now, then preemptive call
    // will have in_first false, will not create SQL tables, and following
    // calls relying on those tables will fail.
    //
    // Therefore, as above, adapters MUST guard init() with a mutex.
    // 
    // Therefore, first session
    // is to be created and last session to be deleted alone, and not
    // concurently to other sessions creation or deletion.
    // We expect adapters to enforce this either by implicitely creating a
    // client session, or by using synchronization primitive to protect
    // creation/deletion of first/last session from the app.

    if (session == NULL)
        return PEP_ILLEGAL_VALUE;

    *session = NULL;

    pEpSession *_session = calloc(1, sizeof(pEpSession));
    assert(_session);
    if (_session == NULL)
        goto enomem;

    _session->version = PEP_ENGINE_VERSION;
    _session->messageToSend = messageToSend;
    _session->inject_sync_event = inject_sync_event;
    _session->ensure_passphrase = ensure_passphrase;
    
    status = init_databases(_session);
    if (status != PEP_STATUS_OK)
        return status;

    if (in_first) {

        status = pEp_sql_init(_session);

        // We need to init a few globals for message id that we'd rather not
        // calculate more than once.
        _init_globals();
    }

    status = pEp_prepare_sql_stmts(_session);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = init_cryptotech(_session, in_first);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = init_transport_system(_session, in_first);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = log_event(_session, "init", "pEp " PEP_ENGINE_VERSION, NULL, NULL);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // runtime config

    // Will now be called by adapter.
    // // clean up invalid keys 
    // status = clean_own_key_defaults(_session);
    // if (status != PEP_STATUS_OK)
    //     goto pEp_error;

    *session = _session;
    
    // Note: Following statement is NOT for any cryptographic/secure functionality; it is
    //       ONLY used for some randomness in generated outer message ID, which are
    //       required by the RFC to be globally unique!
    srand((unsigned int) time(NULL));
    
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    release(_session);
    return status;
}

DYNAMIC_API void release(PEP_SESSION session)
{
    bool out_last = false;
    int _count = --init_count;
    
    if ((_count < -1) || !session)
        return;

    // a small race condition but still a race condition
    // mitigated by calling caveat (see documentation)
    // (release() is to be guarded by a mutex by the caller)
    if (_count == -1)
        out_last = true;

    if (session) {
        free_Sync_state(session);

        if (session->db) {
            pEp_finalize_sql_stmts(session);
            if (session->db) {
                if (out_last) {
                    sqlite3_exec(        
                        session->db,
                        "PRAGMA optimize;\n",
                        NULL,
                        NULL,
                        NULL
                    );
                }    
                sqlite3_close_v2(session->db);
            }
            if (session->system_db)
                sqlite3_close_v2(session->system_db);
        }

        release_transport_system(session, out_last);
        release_cryptotech(session, out_last);
        free(session);
    }
}

DYNAMIC_API void config_passive_mode(PEP_SESSION session, bool enable)
{
    assert(session);
    if (session)
        session->passive_mode = enable;
}

DYNAMIC_API void config_unencrypted_subject(PEP_SESSION session, bool enable)
{
    assert(session);
    if (session)
        session->unencrypted_subject = enable;
}

DYNAMIC_API PEP_STATUS config_passphrase(PEP_SESSION session, const char *passphrase) {
    if (!session)
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
    free(session->curr_passphrase);
    if (!passphrase)
        session->curr_passphrase = NULL;
    else {
        session->curr_passphrase = strdup(passphrase);
        if (!session->curr_passphrase)
            status = PEP_OUT_OF_MEMORY;
    }
    return status;
}

DYNAMIC_API PEP_STATUS config_passphrase_for_new_keys(PEP_SESSION session, bool enable, const char *passphrase) {
    if (!session)
        return PEP_ILLEGAL_VALUE;

    session->new_key_pass_enable = enable;
    PEP_STATUS status = PEP_STATUS_OK;

    free(session->generation_passphrase);
    if (EMPTYSTR(passphrase)) {
        session->generation_passphrase = NULL;
    } else {
        session->generation_passphrase = strdup(passphrase);
        if (!session->generation_passphrase)
            status = PEP_OUT_OF_MEMORY;
    }
    return status;    
}

DYNAMIC_API void config_service_log(PEP_SESSION session, bool enable)
{
    assert(session);
    if (session)
        session->service_log = enable;
}

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session,
        const char *title,
        const char *entity,
        const char *description,
        const char *comment
    )
{
    if (!(session && title && entity))
        return PEP_ILLEGAL_VALUE;

#if defined(_WIN32) && !defined(NDEBUG)
    log_output_debug(title, entity, description, comment);
#endif

#if defined(ANDROID) && !defined(NDEBUG)
    __android_log_print(ANDROID_LOG_DEBUG, "pEpEngine", " %s :: %s :: %s :: %s ",
            title, entity, description, comment);
#endif

// N.B. If testing (so NDEBUG not defined) but this message is spam,
//      put -D_PEP_SERVICE_LOG_OFF into CFLAGS/CXXFLAGS     
#if !defined(NDEBUG) && !defined(_PEP_SERVICE_LOG_OFF)
#ifndef NDEBUG
    printf("\x1b[%dm", session->debug_color);
#endif
    fprintf(stdout, "\n*** %s %s %s %s\n", title, entity, description, comment);
#ifndef NDEBUG
    printf("\x1b[0m");
#endif
    session->service_log = true;

    int result;

    sqlite3_reset(session->log);
    sqlite3_bind_text(session->log, 1, title, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->log, 2, entity, -1, SQLITE_STATIC);
    if (description)
        sqlite3_bind_text(session->log, 3, description, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(session->log, 3);
    if (comment)
        sqlite3_bind_text(session->log, 4, comment, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(session->log, 4);
    result = sqlite3_step(session->log);
    sqlite3_reset(session->log);
    
#endif
    return PEP_STATUS_OK; // We ignore errors for this function.
}

DYNAMIC_API PEP_STATUS log_service(
        PEP_SESSION session,
        const char *title,
        const char *entity,
        const char *description,
        const char *comment
    )
{
    if (!session)
        return PEP_ILLEGAL_VALUE;

    if (session->service_log)
        return log_event(session, title, entity, description, comment);
    else
        return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS trustword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        )
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (!(session && word && wsize))
        return PEP_ILLEGAL_VALUE;

    *word = NULL;
    *wsize = 0;

    if (lang == NULL)
        lang = "en";

    // FIXME: should this not be an actual check???
    assert((lang[0] >= 'A' && lang[0] <= 'Z')
            || (lang[0] >= 'a' && lang[0] <= 'z'));
    assert((lang[1] >= 'A' && lang[1] <= 'Z')
            || (lang[1] >= 'a' && lang[1] <= 'z'));
    assert(lang[2] == 0);

    sqlite3_reset(session->trustword);
    sqlite3_bind_text(session->trustword, 1, lang, -1, SQLITE_STATIC);
    sqlite3_bind_int(session->trustword, 2, value);

    const int result = sqlite3_step(session->trustword);
    if (result == SQLITE_ROW) {
        *word = strdup((const char *) sqlite3_column_text(session->trustword,
                    1));
        if (*word)
            *wsize = sqlite3_column_bytes(session->trustword, 1);
        else
            status = PEP_OUT_OF_MEMORY;
    } else
        status = PEP_TRUSTWORD_NOT_FOUND;

    sqlite3_reset(session->trustword);
    return status;
}

DYNAMIC_API PEP_STATUS trustwords(
        PEP_SESSION session, const char *fingerprint, const char *lang,
        char **words, size_t *wsize, int max_words
    )
{
    const char *source = fingerprint;

    if (!(session && fingerprint && words && wsize && max_words >= 0))
        return PEP_ILLEGAL_VALUE;

    *words = NULL;
    *wsize = 0;

    char *buffer = calloc(1, MAX_TRUSTWORDS_SPACE);
    assert(buffer);
    if (buffer == NULL)
        return PEP_OUT_OF_MEMORY;
    char *dest = buffer;

    const size_t fsize = strlen(fingerprint);

    if (!lang || !lang[0])
        lang = "en";

    // FIXME: Should this not be an actual check?
    assert((lang[0] >= 'A' && lang[0] <= 'Z')
            || (lang[0] >= 'a' && lang[0] <= 'z'));
    assert((lang[1] >= 'A' && lang[1] <= 'Z')
            || (lang[1] >= 'a' && lang[1] <= 'z'));
    assert(lang[2] == 0);

    int n_words = 0;
    while (source < fingerprint + fsize) {
        PEP_STATUS _status;
        uint16_t value;
        char *word = NULL;
        size_t _wsize = 0;
        int j;

        for (value=0, j=0; j < 4 && source < fingerprint + fsize; ) {
            if (*source >= 'a' && *source <= 'f')
                value += (*source - 'a' + 10) << (3 - j++) * 4;
            else if (*source >= 'A' && *source <= 'F')
                value += (*source - 'A' + 10) << (3 - j++) * 4;
            else if (*source >= '0' && *source <= '9')
                value += (*source - '0') << (3 - j++) * 4;
            
            source++;
        }

        _status = trustword(session, value, lang, &word, &_wsize);
        if (_status == PEP_OUT_OF_MEMORY) {
            free(buffer);
            return PEP_OUT_OF_MEMORY;
        }
        if (word == NULL) {
            free(buffer);
            return PEP_TRUSTWORD_NOT_FOUND;
        }

        if (dest + _wsize < buffer + MAX_TRUSTWORDS_SPACE - 1) {
            strncpy(dest, word, _wsize);
            free(word);
            dest += _wsize;
        }
        else {
            free(word);
            break; // buffer full
        }

        ++n_words;
        if (max_words && n_words >= max_words)
            break;
            
        if (source < fingerprint + fsize
                && dest + _wsize < buffer + MAX_TRUSTWORDS_SPACE - 1)
            *dest++ = ' ';
    }

    *words = buffer;
    *wsize = dest - buffer;
    return PEP_STATUS_OK;
}

pEp_identity *new_identity(
        const char *address, const char *fpr, const char *user_id,
        const char *username
    )
{
    pEp_identity *result = calloc(1, sizeof(pEp_identity));
    if (result) {
        if (address) {
            result->address = strdup(address);
            assert(result->address);
            if (result->address == NULL) {
                free(result);
                return NULL;
            }
        }
        if (fpr) {
            result->fpr = strdup(fpr);
            assert(result->fpr);
            if (result->fpr == NULL) {
                free_identity(result);
                return NULL;
            }
        }
        if (user_id) {
            result->user_id = strdup(user_id);
            assert(result->user_id);
            if (result->user_id == NULL) {
                free_identity(result);
                return NULL;
            }
        }
        if (username) {
            result->username = strdup(username);
            assert(result->username);
            if (result->username == NULL) {
                free_identity(result);
                return NULL;
            }
        }
    }
    return result;
}

pEp_identity *identity_dup(const pEp_identity *src)
{
    pEp_identity* dup = NULL;
    if (src) {
        dup = new_identity(src->address, src->fpr, src->user_id,
                src->username);
        assert(dup);
        if (dup == NULL)
            return NULL;
        
        dup->comm_type = src->comm_type;
        dup->lang[0] = src->lang[0];
        dup->lang[1] = src->lang[1];
        dup->lang[2] = 0;
        dup->flags = src->flags;
        dup->me = src->me;
        dup->major_ver = src->major_ver;
        dup->minor_ver = src->minor_ver;
        dup->enc_format = src->enc_format;
    }
    return dup;
}

void free_identity(pEp_identity *identity)
{
    if (identity) {
        free(identity->address);
        free(identity->fpr);
        free(identity->user_id);
        free(identity->username);
        free(identity);
    }
}

DYNAMIC_API PEP_STATUS get_default_own_userid(
        PEP_SESSION session, 
        char** userid
    )
{
    
    if (!session || !userid)
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
    char* retval = NULL;
    
    sqlite3_reset(session->get_default_own_userid);

    const int result = sqlite3_step(session->get_default_own_userid);
    const char* id;
    
    switch (result) {
        case SQLITE_ROW:
            id = (const char *) sqlite3_column_text(session->get_default_own_userid, 0);
            if (!id) {
                // Shouldn't happen.
                status = PEP_UNKNOWN_ERROR;
            }
            else {
                retval = strdup(id);
                if (!retval)
                    status = PEP_OUT_OF_MEMORY;
            }
            break;
        default:
            // Technically true, given how we find it, but FIXME we need a more descriptive error
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    *userid = retval;

    sqlite3_reset(session->get_default_own_userid);
    
    return status;
}

DYNAMIC_API PEP_STATUS get_userid_alias_default(
        PEP_SESSION session, 
        const char* alias_id,
        char** default_id) {
            
    if (!(session && alias_id && alias_id[0] && default_id))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    char* retval = NULL;

    sqlite3_reset(session->get_userid_alias_default);
    sqlite3_bind_text(session->get_userid_alias_default, 1, alias_id, -1, SQLITE_STATIC);

    const char* tempid;
    
    const int result = sqlite3_step(session->get_userid_alias_default);
    switch (result) {
    case SQLITE_ROW:
        tempid = (const char *) sqlite3_column_text(session->get_userid_alias_default, 0);
        if (tempid) {
            retval = strdup(tempid);
            assert(retval);
            if (retval == NULL)
                return PEP_OUT_OF_MEMORY;
        }
    
        *default_id = retval;
        break;
    default:
        status = PEP_CANNOT_FIND_ALIAS;
        *default_id = NULL;
    }

    sqlite3_reset(session->get_userid_alias_default);
    return status;            
}

DYNAMIC_API PEP_STATUS set_userid_alias (
        PEP_SESSION session, 
        const char* default_id,
        const char* alias_id) {
            
    int result;

    if (!(session && default_id && alias_id && 
          default_id[0] != '\0' && alias_id[0] != '\0'))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_exec(session->db, "BEGIN TRANSACTION ;", NULL, NULL, NULL);

    sqlite3_reset(session->add_userid_alias);
    sqlite3_bind_text(session->add_userid_alias, 1, default_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_userid_alias, 2, alias_id, -1,
            SQLITE_STATIC);
        
    result = sqlite3_step(session->add_userid_alias);

    sqlite3_reset(session->add_userid_alias);
    if (result != SQLITE_DONE) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);        
        return PEP_CANNOT_SET_ALIAS;
    }
    sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
        

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS get_identity(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *_identity = NULL;

    if (!(session && address && address[0] && identity))
        return PEP_ILLEGAL_VALUE;

    *identity = NULL;

    sqlite3_reset(session->get_identity);
    sqlite3_bind_text(session->get_identity, 1, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_identity, 2, user_id, -1, SQLITE_STATIC);

    const int result = sqlite3_step(session->get_identity);
    switch (result) {
    case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identity, 0),
                user_id,
                (const char *) sqlite3_column_text(session->get_identity, 1)
                );
        assert(_identity);
        if (_identity == NULL) {
            sqlite3_reset(session->get_identity);
            return PEP_OUT_OF_MEMORY;
        }

        _identity->comm_type = (PEP_comm_type)
            sqlite3_column_int(session->get_identity, 2);
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identity, 3);
        if (_lang && _lang[0]) {
            assert(_lang[0] >= 'a' && _lang[0] <= 'z');
            assert(_lang[1] >= 'a' && _lang[1] <= 'z');
            assert(_lang[2] == 0);
            _identity->lang[0] = _lang[0];
            _identity->lang[1] = _lang[1];
            _identity->lang[2] = 0;
        }
        _identity->flags = (unsigned int)
            sqlite3_column_int(session->get_identity, 4);
        _identity->me = (unsigned int)
            sqlite3_column_int(session->get_identity, 5);
        _identity->major_ver =
            sqlite3_column_int(session->get_identity, 6);
        _identity->minor_ver =
            sqlite3_column_int(session->get_identity, 7);
        _identity->enc_format =    
            sqlite3_column_int(session->get_identity, 8);    
        *identity = _identity;
        break;
    default:
        sqlite3_reset(session->get_identity);
        status = PEP_CANNOT_FIND_IDENTITY;
        *identity = NULL;
    }

    sqlite3_reset(session->get_identity);
    return status;
}

PEP_STATUS get_identities_by_userid(
        PEP_SESSION session,
        const char *user_id,
        identity_list **identities
    )
{
    if (!session || !identities || EMPTYSTR(user_id))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity* ident = NULL;

    *identities = new_identity_list(NULL);

    sqlite3_reset(session->get_identities_by_userid);
    sqlite3_bind_text(session->get_identities_by_userid, 1, user_id, -1, SQLITE_STATIC);

    int result = -1;
    while ((result = sqlite3_step(session->get_identities_by_userid)) == SQLITE_ROW) {
            // "select address, identity.main_key_id, username, comm_type, lang,"
            // "   identity.flags | pgp_keypair.flags,"
            // "   is_own"
            // "   from identity"
            // "   join person on id = identity.user_id"
            // "   join pgp_keypair on fpr = identity.main_key_id"
            // "   join trust on id = trust.user_id"
            // "       and pgp_keypair_fpr = identity.main_key_id"    
            // "   where identity.user_id = ?1" 
            // "   order by is_own desc, "
            // "   timestamp desc; ";

        ident = new_identity(
                    (const char *) sqlite3_column_text(session->get_identities_by_userid, 0),
                    (const char *) sqlite3_column_text(session->get_identities_by_userid, 1),                
                    user_id,
                    (const char *) sqlite3_column_text(session->get_identities_by_userid, 2)
                );
                
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_identities_by_userid);
            return PEP_OUT_OF_MEMORY;
        }

        ident->comm_type = (PEP_comm_type)
            sqlite3_column_int(session->get_identities_by_userid, 3);
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identities_by_userid, 4);
        if (_lang && _lang[0]) {
            assert(_lang[0] >= 'a' && _lang[0] <= 'z');
            assert(_lang[1] >= 'a' && _lang[1] <= 'z');
            assert(_lang[2] == 0);
            ident->lang[0] = _lang[0];
            ident->lang[1] = _lang[1];
            ident->lang[2] = 0;
        }
        ident->flags = (unsigned int)
            sqlite3_column_int(session->get_identities_by_userid, 5);
        ident->me = (unsigned int)
            sqlite3_column_int(session->get_identities_by_userid, 6);
        ident->major_ver =
            sqlite3_column_int(session->get_identities_by_userid, 7);
        ident->minor_ver =
            sqlite3_column_int(session->get_identities_by_userid, 8);
        ident->enc_format =    
            sqlite3_column_int(session->get_identities_by_userid, 9);    
            
    
        identity_list_add(*identities, ident);
        ident = NULL;
    }

    if ((*identities)->ident == NULL) {
        free_identity_list(*identities);
        *identities = NULL;
        status = PEP_CANNOT_FIND_IDENTITY;
    }
            
    sqlite3_reset(session->get_identities_by_userid);

    return status;
}

PEP_STATUS get_identities_by_main_key_id(
        PEP_SESSION session,
        const char *fpr,
        identity_list **identities
    )
{
    if (!session || !identities || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity* ident = NULL;

    *identities = new_identity_list(NULL);

    sqlite3_reset(session->get_identities_by_main_key_id);
    sqlite3_bind_text(session->get_identities_by_main_key_id, 1, fpr, -1, SQLITE_STATIC);

    int result = -1;
    
    while ((result = sqlite3_step(session->get_identities_by_main_key_id)) == SQLITE_ROW) {
        ident = new_identity(
                    (const char *) sqlite3_column_text(session->get_identities_by_main_key_id, 0),
                    fpr,
                    (const char *) sqlite3_column_text(session->get_identities_by_main_key_id, 1),                
                    (const char *) sqlite3_column_text(session->get_identities_by_main_key_id, 2)
                );
                
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_identities_by_main_key_id);
            return PEP_OUT_OF_MEMORY;
        }

        ident->comm_type = (PEP_comm_type)
            sqlite3_column_int(session->get_identities_by_main_key_id, 3);
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identities_by_main_key_id, 4);
        if (_lang && _lang[0]) {
            assert(_lang[0] >= 'a' && _lang[0] <= 'z');
            assert(_lang[1] >= 'a' && _lang[1] <= 'z');
            assert(_lang[2] == 0);
            ident->lang[0] = _lang[0];
            ident->lang[1] = _lang[1];
            ident->lang[2] = 0;
        }
        ident->flags = (unsigned int)
            sqlite3_column_int(session->get_identities_by_main_key_id, 5);
        ident->me = (unsigned int)
            sqlite3_column_int(session->get_identities_by_main_key_id, 6);
        ident->major_ver =
            sqlite3_column_int(session->get_identities_by_main_key_id, 7);
        ident->minor_ver =
            sqlite3_column_int(session->get_identities_by_main_key_id, 8);
        ident->enc_format =    
            sqlite3_column_int(session->get_identities_by_main_key_id, 9);                
    
        identity_list_add(*identities, ident);
        ident = NULL;
    }

    if ((*identities)->ident == NULL) {
        free_identity_list(*identities);
        *identities = NULL;
        status = PEP_CANNOT_FIND_IDENTITY;
    }
            
    sqlite3_reset(session->get_identities_by_main_key_id);

    return status;
}

PEP_STATUS get_identity_without_trust_check(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *_identity = NULL;

    if (!(session && address && address[0] && identity))
        return PEP_ILLEGAL_VALUE;

    *identity = NULL;

    sqlite3_reset(session->get_identity_without_trust_check);
    sqlite3_bind_text(session->get_identity_without_trust_check, 1, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_identity_without_trust_check, 2, user_id, -1, SQLITE_STATIC);

    const int result = sqlite3_step(session->get_identity_without_trust_check);
    switch (result) {
    case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identity_without_trust_check, 0),
                user_id,
                (const char *) sqlite3_column_text(session->get_identity_without_trust_check, 1)
                );
        assert(_identity);
        if (_identity == NULL) {
            sqlite3_reset(session->get_identity_without_trust_check);
            return PEP_OUT_OF_MEMORY;
        }

        _identity->comm_type = PEP_ct_unknown;
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identity_without_trust_check, 2);
        if (_lang && _lang[0]) {
            assert(_lang[0] >= 'a' && _lang[0] <= 'z');
            assert(_lang[1] >= 'a' && _lang[1] <= 'z');
            assert(_lang[2] == 0);
            _identity->lang[0] = _lang[0];
            _identity->lang[1] = _lang[1];
            _identity->lang[2] = 0;
        }
        _identity->flags = (unsigned int)
            sqlite3_column_int(session->get_identity_without_trust_check, 3);
        _identity->me = (unsigned int)
            sqlite3_column_int(session->get_identity_without_trust_check, 4);
        _identity->major_ver =
            sqlite3_column_int(session->get_identity_without_trust_check, 5);
        _identity->minor_ver =
            sqlite3_column_int(session->get_identity_without_trust_check, 6);
        _identity->enc_format =    
            sqlite3_column_int(session->get_identity_without_trust_check, 7);                
    
        *identity = _identity;
        break;
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
        *identity = NULL;
    }

    sqlite3_reset(session->get_identity_without_trust_check);
    return status;
}


PEP_STATUS get_identities_by_address(
        PEP_SESSION session,
        const char *address,
        identity_list** id_list
    )
{

    if (!(session && address && address[0] && id_list))
        return PEP_ILLEGAL_VALUE;

    *id_list = NULL;
    identity_list* ident_list = NULL;

    sqlite3_reset(session->get_identities_by_address);
    sqlite3_bind_text(session->get_identities_by_address, 1, address, -1, SQLITE_STATIC);
    int result;

    while ((result = sqlite3_step(session->get_identities_by_address)) == SQLITE_ROW) {
        //"select user_id, main_key_id, username, comm_type, lang,"
        //"   identity.flags, is_own"
        pEp_identity *ident = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identities_by_address, 1),
                (const char *) sqlite3_column_text(session->get_identities_by_address, 0),
                (const char *) sqlite3_column_text(session->get_identities_by_address, 2)
                );
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_identities_by_address);
            return PEP_OUT_OF_MEMORY;
        }

        ident->comm_type = PEP_ct_unknown;
        
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identities_by_address, 3);
        if (_lang && _lang[0]) {
            assert(_lang[0] >= 'a' && _lang[0] <= 'z');
            assert(_lang[1] >= 'a' && _lang[1] <= 'z');
            assert(_lang[2] == 0);
            ident->lang[0] = _lang[0];
            ident->lang[1] = _lang[1];
            ident->lang[2] = 0;
        }
        ident->flags = (unsigned int)
            sqlite3_column_int(session->get_identities_by_address, 4);
        ident->me = (unsigned int)
            sqlite3_column_int(session->get_identities_by_address, 5);
        ident->major_ver =
            sqlite3_column_int(session->get_identities_by_address, 6);
        ident->minor_ver =
            sqlite3_column_int(session->get_identities_by_address, 7);
        ident->enc_format =    
            sqlite3_column_int(session->get_identities_by_address, 8);               
                 
        if (ident_list)
            identity_list_add(ident_list, ident);
        else
            ident_list = new_identity_list(ident);
    }

    sqlite3_reset(session->get_identities_by_address);
    
    *id_list = ident_list;
    
    if (!ident_list)
        return PEP_CANNOT_FIND_IDENTITY;
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       exists_identity_entry()       -->
 *
 *  @brief      checks if an identity entry already exists in the DB    
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *identity        pEp_identity
 *  @param[out]    *exists            bool
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value 
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *
 */
PEP_STATUS exists_identity_entry(PEP_SESSION session, pEp_identity* identity,
                                 bool* exists) {
    if (!session || !exists || !identity || EMPTYSTR(identity->user_id) || EMPTYSTR(identity->address))
        return PEP_ILLEGAL_VALUE;
    
    *exists = false;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    sqlite3_reset(session->exists_identity_entry);
    sqlite3_bind_text(session->exists_identity_entry, 1, identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_identity_entry, 2, identity->user_id, -1,
                      SQLITE_STATIC);
                  
    int result = sqlite3_step(session->exists_identity_entry);

    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *exists = (sqlite3_column_int(session->exists_identity_entry, 0) != 0);
            break;
        }
        default: 
            status = PEP_UNKNOWN_DB_ERROR;
    }

    sqlite3_reset(session->exists_identity_entry);
    return status;
}

PEP_STATUS exists_trust_entry(PEP_SESSION session, pEp_identity* identity,
                              bool* exists) {
    if (!session || !exists || !identity || EMPTYSTR(identity->user_id) || EMPTYSTR(identity->fpr))
        return PEP_ILLEGAL_VALUE;
    
    *exists = false;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    sqlite3_reset(session->exists_trust_entry);
    sqlite3_bind_text(session->exists_trust_entry, 1, identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_trust_entry, 2, identity->fpr, -1,
                      SQLITE_STATIC);
                  
    int result = sqlite3_step(session->exists_trust_entry);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *exists = (sqlite3_column_int(session->exists_trust_entry, 0) != 0);
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    
    sqlite3_reset(session->exists_trust_entry);
    return status;
}

PEP_STATUS set_pgp_keypair(PEP_SESSION session, const char* fpr) {
    if (!session || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;
        
    int result;
    
    sqlite3_reset(session->set_pgp_keypair);
    sqlite3_bind_text(session->set_pgp_keypair, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->set_pgp_keypair);
    sqlite3_reset(session->set_pgp_keypair);
    if (result != SQLITE_DONE) {
        return PEP_CANNOT_SET_PGP_KEYPAIR;
    }
    
    return PEP_STATUS_OK;
}

PEP_STATUS clear_trust_info(PEP_SESSION session,
                            const char* user_id,
                            const char* fpr) {
    if (!session || EMPTYSTR(fpr) || EMPTYSTR(user_id))
        return PEP_ILLEGAL_VALUE;
        
    int result;
    
    sqlite3_reset(session->clear_trust_info);
    sqlite3_bind_text(session->clear_trust_info, 1, user_id, -1,
            SQLITE_STATIC);    
    sqlite3_bind_text(session->clear_trust_info, 2, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->clear_trust_info);
    sqlite3_reset(session->clear_trust_info);
    if (result != SQLITE_DONE) {
        return PEP_UNKNOWN_ERROR;
    }
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _set_or_update_trust()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                session handle    
 *  @param[in]    *identity            pEp_identity
 *  @param[in]    *set_or_update        sqlite3_stmt
 *
 *  @retval     PEP_STATUS_OK     
 *  @retval     PEP_CANNOT_SET_TRUST          
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *
 */
static PEP_STATUS _set_or_update_trust(PEP_SESSION session,
                                       pEp_identity* identity,
                                       sqlite3_stmt* set_or_update) {
    
    if (!session || !identity || EMPTYSTR(identity->user_id) || EMPTYSTR(identity->fpr))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = set_pgp_keypair(session, identity->fpr);
    if (status != PEP_STATUS_OK)
        return status;
        
    int result;
                
    sqlite3_reset(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_int(set_or_update, 3, identity->comm_type);
    result = sqlite3_step(set_or_update);
    assert(result == SQLITE_DONE);
    sqlite3_reset(set_or_update);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _set_or_update_identity_entry()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                session handle    
 *  @param[in]    *identity            pEp_identity
 *  @param[in]    *set_or_update        sqlite3_stmt
 *
 *  @retval     PEP_STATUS_OK 
 *  @retval     PEP_CANNOT_SET_IDENTITY
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *
 */
static PEP_STATUS _set_or_update_identity_entry(PEP_SESSION session,
                                                pEp_identity* identity,
                                                sqlite3_stmt* set_or_update) {
                      
    if (!session || !identity || !identity->user_id || !identity->address)
        return PEP_ILLEGAL_VALUE;
                                              
    sqlite3_reset(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, EMPTYSTR(identity->fpr) ? NULL : identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 3, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 4, identity->username, -1,
                      SQLITE_STATIC);
    sqlite3_bind_int(set_or_update, 5, identity->flags);
    sqlite3_bind_int(set_or_update, 6, identity->me);
    sqlite3_bind_int(set_or_update, 7, identity->major_ver);
    sqlite3_bind_int(set_or_update, 8, identity->minor_ver);
        
    int result = sqlite3_step(set_or_update);
    sqlite3_reset(set_or_update);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _set_or_update_person()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session             session handle        
 *  @param[in]    *identity            pEp_identity
 *  @param[in]    *set_or_update        sqlite3_stmt
 *
 *  @retval     PEP_STATUS_OK 
 *  @retval     PEP_CANNOT_SET_IDENTITY
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
static PEP_STATUS _set_or_update_person(PEP_SESSION session,
                                        pEp_identity* identity,
                                        sqlite3_stmt* set_or_update) {
                        
    if (!session || !identity || !identity->user_id || !identity->username)
        return PEP_ILLEGAL_VALUE;
        
    sqlite3_reset(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, identity->username, -1,
            SQLITE_STATIC);
    if (identity->lang[0])
        sqlite3_bind_text(set_or_update, 3, identity->lang, 2,
                SQLITE_STATIC);
    else
        sqlite3_bind_null(set_or_update, 3);
    sqlite3_bind_text(set_or_update, 4, EMPTYSTR(identity->fpr) ? NULL : identity->fpr, -1,
                      SQLITE_STATIC);
    int result = sqlite3_step(set_or_update);
    sqlite3_reset(set_or_update);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;
    
    return PEP_STATUS_OK;                                         
}

PEP_STATUS set_or_update_with_identity(PEP_SESSION session,
                                       pEp_identity* identity,
                                       PEP_STATUS (* set_function)(PEP_SESSION, pEp_identity*, sqlite3_stmt*),
                                       PEP_STATUS (* exists_function)(PEP_SESSION, pEp_identity*, bool*),                                       
                                       sqlite3_stmt* update_query,
                                       sqlite3_stmt* set_query,
                                       bool guard_transaction) {

    if (guard_transaction) {
        sqlite3_exec(session->db, "BEGIN TRANSACTION ;", NULL, NULL, NULL);
    }
    bool exists = false;
    PEP_STATUS status = exists_function(session, identity, &exists);
    
    if (status == PEP_STATUS_OK) {
        if (exists) {
            status = set_function(session, identity, update_query);
        }
        else {
            status = set_function(session, identity, set_query);                                              
        }                    
    }   
    if (guard_transaction) {        
        if (status != PEP_STATUS_OK)
            sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        else 
            sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
    }                      
    return status;
}

/**
 *  @internal
 *
 *  <!--       _set_trust_internal()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle    
 *  @param[in]    *identity                pEp_identity
 *  @param[in]    guard_transaction        bool
 *
 */
PEP_STATUS _set_trust_internal(PEP_SESSION session, pEp_identity* identity,
                               bool guard_transaction) {
    return set_or_update_with_identity(session, identity,
                                       _set_or_update_trust,
                                        exists_trust_entry,
                                        session->update_trust,
                                        session->set_trust,
                                        guard_transaction);
}

// This is the TOP-LEVEL function. If you're calling from set_identity,
// you can't use this one.
PEP_STATUS set_trust(PEP_SESSION session, pEp_identity* identity) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    status = _set_trust_internal(session, identity, true);
    if (status == PEP_STATUS_OK) {
        if ((identity->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
            status = set_as_pEp_user(session, identity);
    }
    return status;
}

PEP_STATUS set_person(PEP_SESSION session, pEp_identity* identity,
                      bool guard_transaction) {
    return set_or_update_with_identity(session, identity,
                                       _set_or_update_person,
                                       exists_person,
                                       session->update_person,
                                       session->set_person,
                                       guard_transaction);
}

/**
 *  @internal
 *
 *  <!--       set_identity_entry()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle    
 *  @param[in]    *identity                pEp_identity
 *  @param[in]    guard_transaction        bool
 *
 */
PEP_STATUS set_identity_entry(PEP_SESSION session, pEp_identity* identity,
                              bool guard_transaction) {
    return set_or_update_with_identity(session, identity,
                                       _set_or_update_identity_entry,
                                       exists_identity_entry,
                                       session->update_identity_entry,
                                       session->set_identity_entry,
                                       guard_transaction);
}


// This will NOT call set_as_pEp_user, nor set_pEp_version; you have to do that separately.
DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    int result;

    if (!(session && identity && identity->address &&
                identity->user_id && identity->username))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    
    bool has_fpr = (!EMPTYSTR(identity->fpr));
    
    sqlite3_exec(session->db, "BEGIN TRANSACTION ;", NULL, NULL, NULL);

    if (identity->lang[0]) {
        assert(identity->lang[0] >= 'a' && identity->lang[0] <= 'z');
        assert(identity->lang[1] >= 'a' && identity->lang[1] <= 'z');
        assert(identity->lang[2] == 0);
    }

    if (has_fpr) {
        sqlite3_reset(session->set_pgp_keypair);
        sqlite3_bind_text(session->set_pgp_keypair, 1, identity->fpr, -1,
                SQLITE_STATIC);
        result = sqlite3_step(session->set_pgp_keypair);
        sqlite3_reset(session->set_pgp_keypair);
        if (result != SQLITE_DONE) {
            sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
            return PEP_CANNOT_SET_PGP_KEYPAIR;
        }
    }

    // We do this because there are checks in set_person for
    // aliases, which modify the identity object on return.
    pEp_identity* ident_copy = identity_dup(identity); 
    if (!ident_copy)
        return PEP_OUT_OF_MEMORY;

    // For now, we ALWAYS set the person.username.
    status = set_person(session, ident_copy, false);
    if (status != PEP_STATUS_OK) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        goto pEp_free;
    }

    status = set_identity_entry(session, ident_copy, false);
    if (status != PEP_STATUS_OK) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        goto pEp_free;
    }

    if (has_fpr) {
        status = _set_trust_internal(session, ident_copy, false);
        if (status != PEP_STATUS_OK) {
            sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
            goto pEp_free;
        }
    }
    
    status = set_pEp_version(session, ident_copy, ident_copy->major_ver, ident_copy->minor_ver);
    if (status != PEP_STATUS_OK) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        goto pEp_free;            
    }
    
    result = sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
    if (result == SQLITE_OK)
        status = PEP_STATUS_OK;
    else
        status = PEP_COMMIT_FAILED;

pEp_free:
    free_identity(ident_copy);
    return status;
}

//static const char* sql_force_set_identity_username =
//        "update identity "
//        "   set username = coalesce(username, ?3) "
//        "   where (case when (address = ?1) then (1)"
//        "               when (lower(address) = lower(?1)) then (1)"
//        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1) "
//        "               else 0 "
//        "          end) = 1 "
//        "          and user_id = ?2 ;";

PEP_STATUS force_set_identity_username(PEP_SESSION session, pEp_identity* ident, const char* username) {
    if (!ident || EMPTYSTR(ident->user_id) || EMPTYSTR(ident->address))
        return PEP_ILLEGAL_VALUE;

    // If username is NULL, it's fine. This defaults to sqlite3_bind_null() and clears the username, which
    // might be intended. The caller should decide that before calling this. This is really the force-bludgeon.
    sqlite3_reset(session->force_set_identity_username);
    sqlite3_bind_text(session->force_set_identity_username, 1, ident->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->force_set_identity_username, 2, ident->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->force_set_identity_username, 3, username, -1,
                      SQLITE_STATIC);
    int result = sqlite3_step(session->force_set_identity_username);

    sqlite3_reset(session->force_set_identity_username);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       update_pEp_user_trust_vals()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *user        pEp_identity
 *
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_CANNOT_SET_TRUST
 *
 */
PEP_STATUS update_pEp_user_trust_vals(PEP_SESSION session,
                                      pEp_identity* user) {
    
    if (!session || !user || EMPTYSTR(user->user_id))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->update_trust_to_pEp);
    sqlite3_bind_text(session->update_trust_to_pEp, 1, user->user_id, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->update_trust_to_pEp);
    sqlite3_reset(session->update_trust_to_pEp);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    PEP_STATUS status = upgrade_pEp_version_by_user_id(session, user, 2, 1);
    
    return status;
}


// This ONLY sets the user flag. Must be called outside of a transaction.
DYNAMIC_API PEP_STATUS set_as_pEp_user(PEP_SESSION session, pEp_identity* user) {
        
    if (!session || !user || EMPTYSTR(user->user_id))
        return PEP_ILLEGAL_VALUE;
            
    PEP_STATUS status = PEP_STATUS_OK;
    
    bool person_exists = false;
    
    status = exists_person(session, user, &person_exists);
    
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!person_exists)
        status = set_person(session, user, true);
        
    // Ok, let's set it.
    sqlite3_reset(session->set_as_pEp_user);
    sqlite3_bind_text(session->set_as_pEp_user, 1, user->user_id, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->set_as_pEp_user);
    sqlite3_reset(session->set_as_pEp_user);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    status = update_pEp_user_trust_vals(session, user);
        
    return status;
}

// This ONLY sets the version flag. Must be called outside of a transaction.
PEP_STATUS set_pEp_version(PEP_SESSION session, pEp_identity* ident, unsigned int new_ver_major, unsigned int new_ver_minor) {

    if (!session || !ident || EMPTYSTR(ident->user_id) || EMPTYSTR(ident->address))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->set_pEp_version);
    sqlite3_bind_double(session->set_pEp_version, 1, new_ver_major);
    sqlite3_bind_double(session->set_pEp_version, 2, new_ver_minor);    
    sqlite3_bind_text(session->set_pEp_version, 3, ident->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_pEp_version, 4, ident->user_id, -1,
            SQLITE_STATIC);
    
    int result = sqlite3_step(session->set_pEp_version);
    sqlite3_reset(session->set_pEp_version);
        
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PEP_VERSION;
    
    return PEP_STATUS_OK;
}

// Generally ONLY called by set_as_pEp_user, and ONLY from < 2.0 to 2.0.
PEP_STATUS upgrade_pEp_version_by_user_id(PEP_SESSION session, 
        pEp_identity* ident, 
        unsigned int new_ver_major,
        unsigned int new_ver_minor
    ) 
{

    if (!session || !ident || EMPTYSTR(ident->user_id))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->upgrade_pEp_version_by_user_id);
    sqlite3_bind_int(session->upgrade_pEp_version_by_user_id, 1, new_ver_major);
    sqlite3_bind_int(session->upgrade_pEp_version_by_user_id, 2, new_ver_minor);    
    sqlite3_bind_text(session->upgrade_pEp_version_by_user_id, 3, ident->user_id, -1,
            SQLITE_STATIC);
    
    int result = sqlite3_step(session->upgrade_pEp_version_by_user_id);
    sqlite3_reset(session->upgrade_pEp_version_by_user_id);
        
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PEP_VERSION;
    
    return PEP_STATUS_OK;    
}

PEP_STATUS exists_person(PEP_SESSION session, pEp_identity* identity,
                         bool* exists) {            
            
    if (!session || !exists || !identity || EMPTYSTR(identity->user_id))
        return PEP_ILLEGAL_VALUE;
    
    *exists = false;

    const char* user_id = identity->user_id;
    char* alias_default = NULL;
    
    PEP_STATUS status = get_userid_alias_default(session, user_id, &alias_default);
    
    if (status == PEP_CANNOT_FIND_ALIAS || EMPTYSTR(alias_default)) {
        sqlite3_reset(session->exists_person);
        sqlite3_bind_text(session->exists_person, 1, user_id, -1,
                SQLITE_STATIC);
        int result = sqlite3_step(session->exists_person);
        switch (result) {
            case SQLITE_ROW: {
                // yeah yeah, I know, we could be lazy here, but it looks bad.
                *exists = (sqlite3_column_int(session->exists_person, 0) != 0);
                status = PEP_STATUS_OK;
                break;
            }
            default:
                sqlite3_reset(session->exists_person);
                return PEP_UNKNOWN_DB_ERROR;
        }
        sqlite3_reset(session->exists_person);
    }
    else if (status == PEP_STATUS_OK) {
        *exists = true; // thank you, delete on cascade!
        // FIXME: Should we correct the userid default here? I think we should.
        free(identity->user_id);
        identity->user_id = alias_default; // ownership transfer
    }
    else
        free(alias_default);
            
    return status;
}

/**
 *  @internal
 *
 *  <!--       delete_person()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *user_id        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_UNKNOWN_ERROR
 *
 */
PEP_STATUS delete_person(PEP_SESSION session, const char* user_id) {

    if (!session || EMPTYSTR(user_id))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
    
    sqlite3_reset(session->delete_person);
    sqlite3_bind_text(session->delete_person, 1, user_id, -1,
                      SQLITE_STATIC);
                      
    int result = sqlite3_step(session->delete_person);
    
    if (result != SQLITE_DONE)
        status = PEP_UNKNOWN_ERROR;
        
    sqlite3_reset(session->delete_person);
    return status;
}

DYNAMIC_API PEP_STATUS is_pEp_user(PEP_SESSION session, pEp_identity *identity, bool* is_pEp)
{

    if (!session || !is_pEp || !identity || EMPTYSTR(identity->user_id))
        return PEP_ILLEGAL_VALUE;
    
    *is_pEp = false;
            
    const char* user_id = identity->user_id;
            
    char* alias_default = NULL;
    
    PEP_STATUS status = get_userid_alias_default(session, user_id, &alias_default);
    
    if (status == PEP_CANNOT_FIND_ALIAS || EMPTYSTR(alias_default)) {
        free(alias_default);
        alias_default = strdup(user_id);
    }
    
    sqlite3_reset(session->is_pEp_user);
    sqlite3_bind_text(session->is_pEp_user, 1, user_id, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->is_pEp_user);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *is_pEp = (sqlite3_column_int(session->is_pEp_user, 0) != 0);
            break;
        }
        default:
            sqlite3_reset(session->is_pEp_user);
            free(alias_default);
            return PEP_CANNOT_FIND_PERSON;
    }

    sqlite3_reset(session->is_pEp_user);
    
    free(alias_default);
    return PEP_STATUS_OK;
}

PEP_STATUS is_own_address(PEP_SESSION session, const char* address, bool* is_own_addr)
{

    if (!session || !is_own_addr || EMPTYSTR(address))
        return PEP_ILLEGAL_VALUE;
    
    *is_own_addr = false;

    sqlite3_reset(session->is_own_address);
    sqlite3_bind_text(session->is_own_address, 1, address, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->is_own_address);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *is_own_addr = (sqlite3_column_int(session->is_own_address, 0) != 0);
            break;
        }
        default:
            sqlite3_reset(session->is_own_address);
            return PEP_RECORD_NOT_FOUND;
    }

    sqlite3_reset(session->is_own_address);
    
    return PEP_STATUS_OK;
}

PEP_STATUS bind_own_ident_with_contact_ident(PEP_SESSION session,
                                             pEp_identity* own_ident, 
                                             pEp_identity* contact_ident) {
    if (!own_ident || !contact_ident || 
        !own_ident->address || !own_ident->user_id || !contact_ident->user_id)
        return PEP_ILLEGAL_VALUE;
        
    sqlite3_reset(session->add_into_social_graph);
    sqlite3_bind_text(session->add_into_social_graph, 1, own_ident->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_into_social_graph, 2, own_ident->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_into_social_graph, 3, contact_ident->user_id, -1,
            SQLITE_STATIC);
        
    int result = sqlite3_step(session->add_into_social_graph);
    sqlite3_reset(session->add_into_social_graph);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;
}

// FIXME: should be more like is there a communications relationship,
// since this could be either way
PEP_STATUS has_partner_contacted_address(PEP_SESSION session, const char* partner_id,
                                         const char* own_address, bool* was_contacted) {            
        
    if (!session || !was_contacted || EMPTYSTR(partner_id) || EMPTYSTR(own_address))
        return PEP_ILLEGAL_VALUE;
    
    *was_contacted = false;

    PEP_STATUS status = PEP_STATUS_OK;
    
    sqlite3_reset(session->has_id_contacted_address);
    sqlite3_bind_text(session->has_id_contacted_address, 1, own_address, -1,
            SQLITE_STATIC);            
    sqlite3_bind_text(session->has_id_contacted_address, 2, partner_id, -1,
            SQLITE_STATIC);
            
    int result = sqlite3_step(session->has_id_contacted_address);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *was_contacted = (sqlite3_column_int(session->has_id_contacted_address, 0) != 0);
            status = PEP_STATUS_OK;
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    sqlite3_reset(session->has_id_contacted_address);
            
    return status;
}

// FIXME: problematic - can be multiple and this now matters
PEP_STATUS get_own_ident_for_contact_id(PEP_SESSION session,
                                          const pEp_identity* contact,
                                          pEp_identity** own_ident) {
                                              
    if (!contact || !contact->user_id || !own_ident)
        return PEP_ILLEGAL_VALUE;
        
    char* own_user_id = NULL;
    *own_ident = NULL;
    PEP_STATUS status = get_default_own_userid(session, &own_user_id);
    
    if (status != PEP_STATUS_OK)
        return status;

    sqlite3_reset(session->get_own_address_binding_from_contact);
    sqlite3_bind_text(session->get_own_address_binding_from_contact, 1, own_user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_address_binding_from_contact, 2, contact->user_id, -1,
            SQLITE_STATIC);

    int result = sqlite3_step(session->get_own_address_binding_from_contact);
    
    const char* own_address = NULL;
    
    switch (result) {
        case SQLITE_ROW:
            own_address = (const char *)
                sqlite3_column_text(session->get_own_address_binding_from_contact, 0);
            if (own_address) {
                status = get_identity(session, own_address, own_user_id, own_ident);
                if (status == PEP_STATUS_OK) {
                    if (!own_ident)
                        status = PEP_CANNOT_FIND_IDENTITY;
                }
            }
            break;
        default:
            status = PEP_CANNOT_FIND_IDENTITY;
    }
    
    free(own_user_id);
    return status;
}

PEP_STATUS remove_fpr_as_default(PEP_SESSION session, 
                                 const char* fpr) 
{
    
    if (!session || !fpr)
        return PEP_ILLEGAL_VALUE;
            
    sqlite3_reset(session->remove_fpr_as_identity_default);
    sqlite3_bind_text(session->remove_fpr_as_identity_default, 1, fpr, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->remove_fpr_as_identity_default);
    sqlite3_reset(session->remove_fpr_as_identity_default);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY; 

    sqlite3_reset(session->remove_fpr_as_user_default);
    sqlite3_bind_text(session->remove_fpr_as_user_default, 1, fpr, -1,
                      SQLITE_STATIC);

    result = sqlite3_step(session->remove_fpr_as_user_default);
    sqlite3_reset(session->remove_fpr_as_user_default);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON; 
        
    return PEP_STATUS_OK;
}


PEP_STATUS replace_identities_fpr(PEP_SESSION session, 
                                 const char* old_fpr, 
                                 const char* new_fpr) 
{
    
    if (!old_fpr || !new_fpr)
        return PEP_ILLEGAL_VALUE;
            
    sqlite3_reset(session->replace_identities_fpr);
    sqlite3_bind_text(session->replace_identities_fpr, 1, new_fpr, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->replace_identities_fpr, 2, old_fpr, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->replace_identities_fpr);
    sqlite3_reset(session->replace_identities_fpr);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

PEP_STATUS update_trust_for_fpr(PEP_SESSION session, 
                                const char* fpr, 
                                PEP_comm_type comm_type)
{
    if (!fpr)
        return PEP_ILLEGAL_VALUE;
        
    sqlite3_reset(session->update_trust_for_fpr);
    sqlite3_bind_int(session->update_trust_for_fpr, 1, comm_type);
    sqlite3_bind_text(session->update_trust_for_fpr, 2, fpr, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->update_trust_for_fpr);
    sqlite3_reset(session->update_trust_for_fpr);
    if (result != SQLITE_DONE) {
        return PEP_CANNOT_SET_TRUST;
    }
    
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS set_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        unsigned int flags
    )
{
    int result;

    if (!(session && identity && identity->address && identity->user_id))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->set_identity_flags);
    sqlite3_bind_int(session->set_identity_flags, 1, flags);
    sqlite3_bind_text(session->set_identity_flags, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_identity_flags, 3, identity->user_id, -1,
        SQLITE_STATIC);
        
    result = sqlite3_step(session->set_identity_flags);

    sqlite3_reset(session->set_identity_flags);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    identity->flags |= flags;
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS unset_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        unsigned int flags
    )
{
    int result;

    if (!(session && identity && identity->address && identity->user_id))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->unset_identity_flags);
    sqlite3_bind_int(session->unset_identity_flags, 1, flags);
    sqlite3_bind_text(session->unset_identity_flags, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->unset_identity_flags, 3, identity->user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->unset_identity_flags);
    sqlite3_reset(session->unset_identity_flags);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    identity->flags &= ~flags;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS set_ident_enc_format(
        PEP_SESSION session,
        pEp_identity *identity,
        PEP_enc_format format
    )
{
    int result;

    if (!(session && identity && identity->address && identity->user_id))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->set_ident_enc_format);
    sqlite3_bind_int(session->set_ident_enc_format, 1, format);
    sqlite3_bind_text(session->set_ident_enc_format, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_ident_enc_format, 3, identity->user_id, -1,
        SQLITE_STATIC);
        
    result = sqlite3_step(session->set_ident_enc_format);

    sqlite3_reset(session->set_ident_enc_format);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       get_trust_by_userid()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                session handle    
 *  @param[in]    *user_id            constchar
 *  @param[in]    **trust_list        labeled_int_list_t
 *  
 *  @retval     PEP_ILLEGAL_VALUE   illegal parameter value
 *  @retval     PEP_STATUS_OK
 *
 */
PEP_STATUS get_trust_by_userid(PEP_SESSION session, const char* user_id,
                                           labeled_int_list_t** trust_list)
{
    int result;

    if (!(session && user_id && user_id[0]))
        return PEP_ILLEGAL_VALUE;

    *trust_list = NULL;
    labeled_int_list_t* t_list = NULL;

    sqlite3_reset(session->get_trust_by_userid);
    sqlite3_bind_text(session->get_trust_by_userid, 1, user_id, -1, SQLITE_STATIC);

    while ((result = sqlite3_step(session->get_trust_by_userid)) == SQLITE_ROW) {
        if (!t_list)
            t_list = new_labeled_int_list(sqlite3_column_int(session->get_trust_by_userid, 1),
                                         (const char *) sqlite3_column_text(session->get_trust_by_userid, 0));
        else
            labeled_int_list_add(t_list, sqlite3_column_int(session->get_trust_by_userid, 1),
                                (const char *) sqlite3_column_text(session->get_trust_by_userid, 0));
    }

    sqlite3_reset(session->get_trust_by_userid);

    *trust_list = t_list;
        
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       reconcile_trust()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    t_old        PEP_comm_type
 *  @param[in]    t_new        PEP_comm_type
 *  
 *  @retval     PEP_comm_type   result     
 */
PEP_comm_type reconcile_trust(PEP_comm_type t_old, PEP_comm_type t_new) {
    switch (t_new) {
        case PEP_ct_mistrusted:
        case PEP_ct_key_revoked:
        case PEP_ct_compromised:
        case PEP_ct_key_b0rken:
            return t_new;
        default:
            break;
    }
    switch (t_old) {
        case PEP_ct_mistrusted:
        case PEP_ct_key_revoked:
        case PEP_ct_compromised:
        case PEP_ct_key_b0rken:
            return t_old;
        default:
            break;
    }
    if (t_old < PEP_ct_strong_but_unconfirmed && t_new >= PEP_ct_strong_but_unconfirmed)
        return t_new;
    
    bool confirmed = (t_old & PEP_ct_confirmed) || (t_new & PEP_ct_confirmed);
    PEP_comm_type result = _MAX(t_old, t_new);
    if (confirmed)
        result |= PEP_ct_confirmed;
    return result;
}

/**
 *  @internal
 *
 *  <!--       reconcile_pEp_status()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *old_uid        constchar
 *  @param[in]    *new_uid        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *
 */
PEP_STATUS reconcile_pEp_status(PEP_SESSION session, const char* old_uid,
                                const char* new_uid) {
    PEP_STATUS status = PEP_STATUS_OK;
    // We'll make this easy - if the old one has a pEp status, we set no matter
    // what.
    pEp_identity* ident = new_identity(NULL, NULL, old_uid, NULL);
    bool is_pEp_peep = false;
    status = is_pEp_user(session, ident, &is_pEp_peep);
    if (is_pEp_peep) {
        free(ident->user_id);
        ident->user_id = strdup(new_uid);
        if (!ident->user_id) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
        status = set_as_pEp_user(session, ident);
    }
pEp_free:
    free_identity(ident);
    return status;
}

/**
 *  @internal
 *
 *  <!--       reconcile_usernames()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *old_name        constchar
 *  @param[in]    *new_name        constchar
 *  @param[in]    *address        constchar
 *
 *
 */
const char* reconcile_usernames(const char* old_name, const char* new_name,
                                const char* address) {
    if (EMPTYSTR(old_name)) {
        if (EMPTYSTR(new_name))
            return address;
        else
            return new_name;
    }
    if (EMPTYSTR(new_name))
        return old_name;        
    if (strcmp(new_name, address) == 0)
        return old_name;
    return new_name;        
}

/**
 *  @internal
 *
 *  <!--       reconcile_default_keys()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *old_ident        pEp_identity
 *  @param[in]    *new_ident        pEp_identity
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *
 */
PEP_STATUS reconcile_default_keys(PEP_SESSION session, pEp_identity* old_ident,
                                  pEp_identity* new_ident) {
    PEP_STATUS status = PEP_STATUS_OK;
                                      
    const char* old_fpr = old_ident->fpr;
    const char* new_fpr = new_ident->fpr;
    if (!old_fpr)
        return status;

    PEP_comm_type old_ct = old_ident->comm_type;    
    PEP_comm_type new_ct = new_ident->comm_type;
    
    if (!new_fpr) {
        new_ident->fpr = strdup(old_fpr);
        if (!new_ident->fpr)
            status = PEP_OUT_OF_MEMORY;
        else    
            new_ident->comm_type = old_ct;
        return status;
    }        
    
    if (strcmp(old_fpr, new_fpr) == 0) {
        new_ident->comm_type = reconcile_trust(old_ct, new_ct);
        return status;
    }
    
    bool old_confirmed = old_ct & PEP_ct_confirmed;
    bool new_confirmed = new_ct & PEP_ct_confirmed;
    
    if (new_confirmed)
        return status;
    else if (old_confirmed) {
        free(new_ident->fpr);
        new_ident->fpr = strdup(old_fpr);
        if (!new_ident->fpr)
            status = PEP_OUT_OF_MEMORY;
        else    
            new_ident->comm_type = old_ct;
        return status;
    }
    
    if (old_ct > new_ct) {
        free(new_ident->fpr);
        new_ident->fpr = strdup(old_fpr);
        if (!new_ident->fpr)
            status = PEP_OUT_OF_MEMORY;
        else    
            new_ident->comm_type = old_ct;
    }
    return status;
}

/**
 *  @internal
 *
 *  <!--       reconcile_language()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *old_ident        pEp_identity
 *  @param[in]    *new_ident        pEp_identity
 *
 */
void reconcile_language(pEp_identity* old_ident,
                        pEp_identity* new_ident) {
    if (new_ident->lang[0] == 0) {
        if (old_ident->lang[0] != 0) {
            new_ident->lang[0] = old_ident->lang[0];
            new_ident->lang[1] = old_ident->lang[1];
            new_ident->lang[2] = old_ident->lang[2];
        }
    }
}

// ONLY CALL THIS IF BOTH IDs ARE IN THE PERSON DB, FOOL! </Mr_T>
/**
 *  @internal
 *
 *  <!--       merge_records()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *old_uid        constchar
 *  @param[in]    *new_uid        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *
 */
PEP_STATUS merge_records(PEP_SESSION session, const char* old_uid,
                         const char* new_uid) {
    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity* new_ident = NULL;
    identity_list* old_identities = NULL;
    labeled_int_list_t* trust_list = NULL;
    stringlist_t* touched_keys = new_stringlist(NULL);
    char* main_user_fpr = NULL;

    status = reconcile_pEp_status(session, old_uid, new_uid);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
                        
    bool new_is_pEp = false;
    new_ident = new_identity(NULL, NULL, new_uid, NULL);
    status = is_pEp_user(session, new_ident, &new_is_pEp);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    free(new_ident);
    new_ident = NULL;
        
    status = get_identities_by_userid(session, old_uid, &old_identities);
    if (status == PEP_STATUS_OK && old_identities) {
        identity_list* curr_old = old_identities;
        for (; curr_old && curr_old->ident; curr_old = curr_old->next) {
            pEp_identity* old_ident = curr_old->ident;
            const char* address = old_ident->address;
            status = get_identity(session, address, new_uid, &new_ident);
            if (status == PEP_CANNOT_FIND_IDENTITY) {
                // No new identity matching the old one, so we just set one w. new user_id
                free(old_ident->user_id);
                old_ident->user_id = strdup(new_uid);
                if (!old_ident->user_id) {
                    status = PEP_OUT_OF_MEMORY;
                    goto pEp_free;
                }
                if (new_is_pEp) {
                    PEP_comm_type confirmed_bit = old_ident->comm_type & PEP_ct_confirmed;
                    if ((old_ident->comm_type | PEP_ct_confirmed) == PEP_ct_OpenPGP)
                        old_ident->comm_type = PEP_ct_pEp_unconfirmed | confirmed_bit;
                }
                
                status = set_identity(session, old_ident);
                if (status != PEP_STATUS_OK)
                    goto pEp_free;
            }
            else if (status != PEP_STATUS_OK)
                goto pEp_free;
            else {
                // Ok, so we have two idents which might be in conflict. Have to merge them.
                const char* username = reconcile_usernames(old_ident->username,
                                                           new_ident->username,
                                                           address);
                                                           
                if (!new_ident->username || strcmp(username, new_ident->username) != 0) {
                    free(new_ident->username);
                    new_ident->username = strdup(username);
                    if (!new_ident->username) {
                        status = PEP_OUT_OF_MEMORY;
                        goto pEp_free;
                    }
                }
        
                // Reconcile default keys if they differ, trust if they don't
                status = reconcile_default_keys(session, old_ident, new_ident);
                if (status != PEP_STATUS_OK)
                    goto pEp_free;
                    
                // reconcile languages
                reconcile_language(old_ident, new_ident);

                // reconcile flags - FIXME - is this right?
                new_ident->flags |= old_ident->flags;
                
                // NOTE: In principle, this is only called from update_identity,
                // which would never have me flags set. So I am ignoring them here.
                // if this function is ever USED for that, though, you'll have
                // to go through making sure that the user ids are appropriately
                // aliased, etc. So be careful.
                
                // Set the reconciled record
                    
                status = set_identity(session, new_ident);
                if (status != PEP_STATUS_OK)
                    goto pEp_free;

                if (new_ident->fpr)
                    stringlist_add(touched_keys, new_ident->fpr);
                        
                free_identity(new_ident);
                new_ident = NULL;    
            }
        }
    }
    // otherwise, no need to reconcile identity records. But maybe trust...    
    new_ident = new_identity(NULL, NULL, new_uid, NULL);
    if (!new_ident) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }
    status = get_trust_by_userid(session, old_uid, &trust_list);

    labeled_int_list_t* trust_curr = trust_list;
    for (; trust_curr && trust_curr->label; trust_curr = trust_curr->next) {
        const char* curr_fpr = trust_curr->label;
        new_ident->fpr = strdup(curr_fpr); 
        status = get_trust(session, new_ident);
        switch (status) {
            case PEP_STATUS_OK:
                new_ident->comm_type = reconcile_trust(trust_curr->value,
                                                       new_ident->comm_type);
                break;
            case PEP_CANNOT_FIND_IDENTITY:
                new_ident->comm_type = trust_curr->value;
                break;
            default:
                goto pEp_free;
        }
        new_ident->comm_type = reconcile_trust(trust_curr->value,
                                               new_ident->comm_type);
        if (new_is_pEp) {
            PEP_comm_type confirmed_bit = new_ident->comm_type & PEP_ct_confirmed;
            if ((new_ident->comm_type | PEP_ct_confirmed) == PEP_ct_OpenPGP)
                new_ident->comm_type = PEP_ct_pEp_unconfirmed | confirmed_bit;
        }

        status = set_trust(session, new_ident);
        if (status != PEP_STATUS_OK) {
            goto pEp_free;
        }                  
                              
        free(new_ident->fpr);
        new_ident->fpr = NULL;
        new_ident->comm_type = 0;
    }

    // reconcile the default keys if the new id doesn't have one?
    status = get_main_user_fpr(session, new_uid, &main_user_fpr);
    if (status == PEP_KEY_NOT_FOUND || (status == PEP_STATUS_OK && !main_user_fpr)) {
        status = get_main_user_fpr(session, old_uid, &main_user_fpr);
        if (status == PEP_STATUS_OK && main_user_fpr)
            status = replace_main_user_fpr(session, new_uid, main_user_fpr);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    }
    
    // delete the old user
    status = delete_person(session, old_uid);
    
pEp_free:
    free_identity(new_ident);
    free_identity_list(old_identities);
    free_labeled_int_list(trust_list);
    free_stringlist(touched_keys);
    free(main_user_fpr);
    return status;
}

PEP_STATUS replace_userid(PEP_SESSION session, const char* old_uid,
                          const char* new_uid) {
    
    if (!session || !old_uid || !new_uid)
        return PEP_ILLEGAL_VALUE;

    pEp_identity* temp_ident = new_identity(NULL, NULL, new_uid, NULL);
    bool new_exists = false;
    PEP_STATUS status = exists_person(session, temp_ident, &new_exists);
    free_identity(temp_ident);
    if (status != PEP_STATUS_OK) // DB error
        return status;
        
    if (new_exists)
        return merge_records(session, old_uid, new_uid);

    int result;

    sqlite3_reset(session->replace_userid);
    sqlite3_bind_text(session->replace_userid, 1, new_uid, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_userid, 2, old_uid, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->replace_userid);
#ifndef NDEBUG
    if (result != SQLITE_DONE) {
        const char *errmsg = sqlite3_errmsg(session->db);
        log_event(session, "SQLite3 error", "replace_userid", errmsg, NULL);
    }
#endif // !NDEBUG
    sqlite3_reset(session->replace_userid);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON; // May need clearer retval

    return PEP_STATUS_OK;
}

PEP_STATUS remove_key(PEP_SESSION session, const char* fpr) {
    
    if (!session || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    int result;

    sqlite3_reset(session->delete_key);
    sqlite3_bind_text(session->delete_key, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->delete_key);
    sqlite3_reset(session->delete_key);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR;

    return PEP_STATUS_OK;
}


PEP_STATUS refresh_userid_default_key(PEP_SESSION session, const char* user_id) {
    
    if (!session || !user_id)
        return PEP_ILLEGAL_VALUE;

    int result;

    sqlite3_reset(session->refresh_userid_default_key);
    sqlite3_bind_text(session->refresh_userid_default_key, 1, user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->refresh_userid_default_key);
    sqlite3_reset(session->refresh_userid_default_key);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;    
}

PEP_STATUS replace_main_user_fpr(PEP_SESSION session, const char* user_id,
                                 const char* new_fpr) {
    
    if (!session || !user_id || !new_fpr)
        return PEP_ILLEGAL_VALUE;

    int result;

    sqlite3_reset(session->replace_main_user_fpr);
    sqlite3_bind_text(session->replace_main_user_fpr, 1, new_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr, 2, user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->replace_main_user_fpr);
    sqlite3_reset(session->replace_main_user_fpr);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;
}

PEP_STATUS replace_main_user_fpr_if_equal(PEP_SESSION session, const char* user_id,
                                          const char* new_fpr, const char* compare_fpr) {
    
    if (!session || !user_id || !compare_fpr)
        return PEP_ILLEGAL_VALUE;

    // N.B. new_fpr can be NULL - if there's no key to replace it, this is fine.
    // See sqlite3 documentation on sqlite3_bind_text() and sqlite3_bind_null()

    int result;

    sqlite3_reset(session->replace_main_user_fpr_if_equal);
    sqlite3_bind_text(session->replace_main_user_fpr, 1, new_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr_if_equal, 2, user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr_if_equal, 3, compare_fpr, -1,
            SQLITE_STATIC);            
    result = sqlite3_step(session->replace_main_user_fpr_if_equal);
    sqlite3_reset(session->replace_main_user_fpr_if_equal);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;
}

PEP_STATUS get_main_user_fpr(PEP_SESSION session, 
                             const char* user_id,
                             char** main_fpr)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;
        
    if (!(session && user_id && user_id[0] && main_fpr))
        return PEP_ILLEGAL_VALUE;
        
    *main_fpr = NULL;
    
    sqlite3_reset(session->get_main_user_fpr);
    sqlite3_bind_text(session->get_main_user_fpr, 1, user_id, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->get_main_user_fpr);
    switch (result) {
    case SQLITE_ROW: {
        const char* _fpr = 
            (const char *) sqlite3_column_text(session->get_main_user_fpr, 0);
        if (_fpr) {
            *main_fpr = strdup(_fpr);
            if (!(*main_fpr))
                status = PEP_OUT_OF_MEMORY;
        }
        else {
            status = PEP_KEY_NOT_FOUND;
        }
        break;
    }
    default:
        status = PEP_CANNOT_FIND_PERSON;
    }

    sqlite3_reset(session->get_main_user_fpr);
    return status;
}


PEP_STATUS set_default_identity_fpr(PEP_SESSION session,
                                    const char* user_id,
                                    const char* address,
                                    const char* fpr) {
    if (!session || EMPTYSTR(user_id) || EMPTYSTR(address) || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    // Make sure fpr is in the management DB
    PEP_STATUS status = set_pgp_keypair(session, fpr);
    if (status != PEP_STATUS_OK)
        return status;

    int result;

    sqlite3_reset(session->set_default_identity_fpr);
    sqlite3_bind_text(session->set_default_identity_fpr, 1, user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_default_identity_fpr, 2, address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_default_identity_fpr, 3, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->set_default_identity_fpr);
    sqlite3_reset(session->set_default_identity_fpr);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR;

    return PEP_STATUS_OK;
}



PEP_STATUS get_default_identity_fpr(PEP_SESSION session, 
                                    const char* address,                            
                                    const char* user_id,
                                    char** main_fpr)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;
        
    if (!session || EMPTYSTR(address) || EMPTYSTR(user_id) || !main_fpr)
        return PEP_ILLEGAL_VALUE;
        
    *main_fpr = NULL;
    
    sqlite3_reset(session->get_default_identity_fpr);
    sqlite3_bind_text(session->get_default_identity_fpr, 1, address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_default_identity_fpr, 2, user_id, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->get_default_identity_fpr);
    switch (result) {
    case SQLITE_ROW: {
        const char* _fpr = 
            (const char *) sqlite3_column_text(session->get_default_identity_fpr, 0);
        if (_fpr) {
            *main_fpr = strdup(_fpr);
            if (!(*main_fpr))
                status = PEP_OUT_OF_MEMORY;
        }
        else {
            status = PEP_KEY_NOT_FOUND;
        }
        break;
    }
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->get_default_identity_fpr);
    return status;
}


// Deprecated
DYNAMIC_API PEP_STATUS mark_as_compromized(
        PEP_SESSION session,
        const char *fpr
    )
{
    return mark_as_compromised(session, fpr);
}

DYNAMIC_API PEP_STATUS mark_as_compromised(
        PEP_SESSION session,
        const char *fpr
    )
{
    int result;

    if (!(session && fpr && fpr[0]))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->mark_compromised);
    sqlite3_bind_text(session->mark_compromised, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->mark_compromised);
    sqlite3_reset(session->mark_compromised);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    return PEP_STATUS_OK;
}

DYNAMIC_API void pEp_free(void *p)
{
    free(p);
}

DYNAMIC_API void *pEp_realloc(void *p, size_t size)
{
    return realloc(p, size);
}

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    if (!(session && identity && identity->user_id && identity->user_id[0] &&
                identity->fpr && identity->fpr[0]))
        return PEP_ILLEGAL_VALUE;

    identity->comm_type = PEP_ct_unknown;
    sqlite3_reset(session->get_trust);

    sqlite3_bind_text(session->get_trust, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->get_trust, 2, identity->fpr, -1, SQLITE_STATIC);

    result = sqlite3_step(session->get_trust);
    switch (result) {
    case SQLITE_ROW: {
        int comm_type = (PEP_comm_type) sqlite3_column_int(session->get_trust,
                0);
        identity->comm_type = comm_type;
        break;
    }
 
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->get_trust);
    return status;
}


DYNAMIC_API PEP_STATUS least_trust(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    if (!(session && fpr && comm_type))
        return PEP_ILLEGAL_VALUE;

    *comm_type = PEP_ct_unknown;

    sqlite3_reset(session->least_trust);
    sqlite3_bind_text(session->least_trust, 1, fpr, -1, SQLITE_STATIC);

    result = sqlite3_step(session->least_trust);
    switch (result) {
        case SQLITE_ROW: {
            int _comm_type = sqlite3_column_int(session->least_trust, 0);
            *comm_type = (PEP_comm_type) _comm_type;
            break;
        }
        default:
            // never reached because of sql min()
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->least_trust);
    return status;
}

/**
 *  @internal
 *
 *  <!--       sanitize_pgp_filename()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *filename        char
 *
 */
static void sanitize_pgp_filename(char *filename)
{
    for (int i=0; filename[i]; ++i) {
        switch(filename[i]) {
            // path separators
            case '/':
            case ':':
            case '\\':
            // expansion operators
            case '%':
            case '$':
            // code execution operators
            case '`':
            case '|':
                filename[i] = '-';
                break;
        }
    }
}

DYNAMIC_API PEP_STATUS decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr
    )
{

    if (!(session && ctext && csize && ptext && psize && keylist))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = session->cryptotech[PEP_crypt_OpenPGP].decrypt_and_verify(
            session, ctext, csize, dsigtext, dsigsize, ptext, psize, keylist,
            filename_ptr);

    if (status == PEP_DECRYPT_NO_KEY)
        signal_Sync_event(session, Sync_PR_keysync, CannotDecrypt, NULL);

    if (filename_ptr && *filename_ptr)
        sanitize_pgp_filename(*filename_ptr);

    return status;
}

DYNAMIC_API PEP_STATUS encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{

    if (!(session && keylist && ptext && psize && ctext && csize))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].encrypt_and_sign(session,
            keylist, ptext, psize, ctext, csize);
}

PEP_STATUS encrypt_only(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{

    if (!(session && keylist && ptext && psize && ctext && csize))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].encrypt_only(session,
            keylist, ptext, psize, ctext, csize);
}

PEP_STATUS sign_only(PEP_SESSION session, 
                     const char *data, 
                     size_t data_size, 
                     const char *fpr, 
                     char **sign, 
                     size_t *sign_size) {

    if (!(session && fpr && data && data_size && sign && sign_size))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].sign_only(session,
                                fpr, data, data_size, sign, sign_size);
                         
}

DYNAMIC_API PEP_STATUS probe_encrypt(PEP_SESSION session, const char *fpr)
{
    assert(session);
    if (!session || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    stringlist_t *keylist = new_stringlist(fpr);
    if (!keylist)
        return PEP_OUT_OF_MEMORY;

    char *ctext = NULL;
    size_t csize = 0;
    PEP_STATUS status = encrypt_and_sign(session, keylist, "pEp", 4, &ctext, &csize);
    free(ctext);

    return status;
}


DYNAMIC_API PEP_STATUS verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{

    if (!(session && text && size && signature && sig_size && keylist))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].verify_text(session, text,
            size, signature, sig_size, keylist);
}

DYNAMIC_API PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr)
{

    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].delete_keypair(session, fpr);
}

DYNAMIC_API PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{

    if (!(session && fpr && key_data && size))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].export_key(session, fpr,
            key_data, size, false);
}

DYNAMIC_API PEP_STATUS export_secret_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    if (!(session && fpr && key_data && size))
        return PEP_ILLEGAL_VALUE;

    // don't accept key IDs but full fingerprints only
    if (strlen(fpr) < 16)
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].export_key(session, fpr,
            key_data, size, true);
}

// Deprecated
DYNAMIC_API PEP_STATUS export_secrect_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    return export_secret_key(session, fpr, key_data, size);
}

DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    if (!(session && pattern && keylist))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].find_keys(session, pattern,
            keylist);
}


DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    )
{
    return _generate_keypair(session, identity, false);
}

PEP_STATUS _generate_keypair(PEP_SESSION session, 
                             pEp_identity *identity,
                             bool suppress_event
    )
{
    // N.B. We now allow empty usernames, so the underlying layer for 
    // non-sequoia crypto implementations will have to deal with this.

    if (!(session && identity && identity->address &&
            (identity->fpr == NULL || identity->fpr[0] == 0)))
        return PEP_ILLEGAL_VALUE;

    char* saved_username = NULL;

    // KB: In light of the above, remove? FIXME.
    if (identity->username) {    
        char* at = NULL;
        size_t uname_len = strlen(identity->username);
        
        if (uname_len > 0)
            at = strstr(identity->username, "@"); 
        
        if (at) {
            saved_username = identity->username;
            identity->username = calloc(uname_len + 3, 1);
            if (!identity->username) {
                identity->username = saved_username;
                return PEP_OUT_OF_MEMORY;
            }
            identity->username[0] = '"';
            strlcpy((identity->username) + 1, saved_username, uname_len + 1);
            identity->username[uname_len + 1] = '"';        
        }
    }
        
    PEP_STATUS status =
        session->cryptotech[PEP_crypt_OpenPGP].generate_keypair(session,
                identity);
                
    if (saved_username) {
        free(identity->username);
        identity->username = saved_username;
    }            
    if (status != PEP_STATUS_OK)
        return status;

    if (identity->fpr)
        status = set_pgp_keypair(session, identity->fpr);

    if ((!suppress_event) && (identity->flags & PEP_idf_devicegroup))
        signal_Sync_event(session, Sync_PR_keysync, KeyGen, NULL);

    // add to known keypair DB, as this might not end up being a default
    return status;
}

// SHOULD NOT (in implementation) ever return PASSPHRASE errors
DYNAMIC_API PEP_STATUS get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    )
{
    if (!(session && fpr && comm_type))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].get_key_rating(session, fpr,
            comm_type);
}

DYNAMIC_API PEP_STATUS import_key(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_keys)
{
    return import_key_with_fpr_return(session, key_data, size, private_keys, NULL, NULL);
}

DYNAMIC_API PEP_STATUS import_key_with_fpr_return(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_keys,
        stringlist_t** imported_keys,
        uint64_t* changed_public_keys        
    )
{
    if (!(session && key_data))
        return PEP_ILLEGAL_VALUE;
        
    if (imported_keys && !*imported_keys && changed_public_keys)
        *changed_public_keys = 0;

    return session->cryptotech[PEP_crypt_OpenPGP].import_key(session, key_data,
            size, private_keys, imported_keys, changed_public_keys);
}

DYNAMIC_API PEP_STATUS recv_key(PEP_SESSION session, const char *pattern)
{   
    if (!(session && pattern))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].recv_key(session, pattern);
}

DYNAMIC_API PEP_STATUS send_key(PEP_SESSION session, const char *pattern)
{
    if (!(session && pattern))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].send_key(session, pattern);
}

DYNAMIC_API PEP_STATUS renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    )
{
    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].renew_key(session, fpr, ts);
}

DYNAMIC_API PEP_STATUS revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    )
{
    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    // Check to see first if it is revoked
    bool revoked = false;
    PEP_STATUS status = key_revoked(session, fpr, &revoked);
    if (status != PEP_STATUS_OK)
        return status;
        
    if (revoked)
        return PEP_STATUS_OK;

    return session->cryptotech[PEP_crypt_OpenPGP].revoke_key(session, fpr,
            reason);
}

DYNAMIC_API PEP_STATUS key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    )
{
    if (!(session && fpr && expired))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].key_expired(session, fpr,
            when, expired);
}

DYNAMIC_API PEP_STATUS key_revoked(
       PEP_SESSION session,
       const char *fpr,
       bool *revoked
   )
{    
    if (!(session && fpr && revoked))
        return PEP_ILLEGAL_VALUE;
    
    return session->cryptotech[PEP_crypt_OpenPGP].key_revoked(session, fpr,
            revoked);
}

DYNAMIC_API PEP_STATUS config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite)
{
    if (!session)
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].config_cipher_suite(session, suite);
}

/**
 *  @internal
 *
 *  <!--       _clean_log_value()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *text        char
 *
 */
static void _clean_log_value(char *text)
{
    if (text) {
        for (char *c = text; *c; c++) {
            if (*c < 32 && *c != '\n')
                *c = 32;
            else if (*c == '"')
                *c = '\'';
        }
    }
}

/**
 *  @internal
 *
 *  <!--       _concat_string()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *str1        char
 *  @param[in]    *str2        const char
 *  @param[in]    delim        char
 *  
 */
static char *_concat_string(char *str1, const char *str2, char delim)
{
    str2 = str2 ? str2 : "";
    size_t len1 = str1 ? strlen(str1) : 0;
    size_t len2 = strlen(str2);
    size_t len = len1 + len2 + 3;
    char * result = realloc(str1, len + 1);

    if (result) {
        result[len1] = '"';
        strcpy(result + len1 + 1, str2);
        result[len - 2] = '"';
        result[len - 1] = delim;
        result[len] = 0;
    }
    else {
        free(str1);
    }

    return result;
}

DYNAMIC_API PEP_STATUS get_crashdump_log(
        PEP_SESSION session,
        int maxlines,
        char **logdata
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *_logdata= NULL;

    if (!(session && logdata && maxlines >= 0 && maxlines <=
            CRASHDUMP_MAX_LINES))
        return PEP_ILLEGAL_VALUE;

    *logdata = NULL;

    int limit = maxlines ? maxlines : CRASHDUMP_DEFAULT_LINES;
    const char *timestamp = NULL;
    const char *title = NULL;
    const char *entity = NULL;
    const char *desc = NULL;
    const char *comment = NULL;

    sqlite3_reset(session->crashdump);
    sqlite3_bind_int(session->crashdump, 1, limit);

    int result;

    do {
        result = sqlite3_step(session->crashdump);
        switch (result) {
        case SQLITE_ROW:
            timestamp = (const char *) sqlite3_column_text(session->crashdump,
                    0);
            title   = (const char *) sqlite3_column_text(session->crashdump,
                    1);
            entity  = (const char *) sqlite3_column_text(session->crashdump,
                    2);
            desc    = (const char *) sqlite3_column_text(session->crashdump,
                    3);
            comment = (const char *) sqlite3_column_text(session->crashdump,
                    4);

            _logdata = _concat_string(_logdata, timestamp, ',');
            if (_logdata == NULL)
                goto enomem;

            _logdata = _concat_string(_logdata, title, ',');
            if (_logdata == NULL)
                goto enomem;

            _logdata = _concat_string(_logdata, entity, ',');
            if (_logdata == NULL)
                goto enomem;

            _logdata = _concat_string(_logdata, desc, ',');
            if (_logdata == NULL)
                goto enomem;

            _logdata = _concat_string(_logdata, comment, '\n');
            if (_logdata == NULL)
                goto enomem;

            _clean_log_value(_logdata);
            break;

        case SQLITE_DONE:
            break;

        default:
            status = PEP_UNKNOWN_ERROR;
            result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);

    sqlite3_reset(session->crashdump);
    if (status == PEP_STATUS_OK) {
        if (_logdata) {
            *logdata = _logdata;
        }
        else {
            *logdata = strdup("");
            if (!*logdata)
                goto enomem;
        }
    }

    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}

DYNAMIC_API PEP_STATUS get_languagelist(
        PEP_SESSION session,
        char **languages
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *_languages= NULL;

    if (!(session && languages))
        return PEP_ILLEGAL_VALUE;

    *languages = NULL;

    const char *lang = NULL;
    const char *name = NULL;
    const char *phrase = NULL;

    sqlite3_reset(session->languagelist);

    int result;

    do {
        result = sqlite3_step(session->languagelist);
        switch (result) {
        case SQLITE_ROW:
            lang = (const char *) sqlite3_column_text(session->languagelist,
                    0);
            name = (const char *) sqlite3_column_text(session->languagelist,
                    1);
            phrase = (const char *) sqlite3_column_text(session->languagelist,
                    2);

            _languages = _concat_string(_languages, lang, ',');
            if (_languages == NULL)
                goto enomem;

            _languages = _concat_string(_languages, name, ',');
            if (_languages == NULL)
                goto enomem;

            _languages = _concat_string(_languages, phrase, '\n');
            if (_languages == NULL)
                goto enomem;

            break;

        case SQLITE_DONE:
            break;

        default:
            status = PEP_UNKNOWN_DB_ERROR;
            result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);

    sqlite3_reset(session->languagelist);
    if (status == PEP_STATUS_OK)
        *languages = _languages;

    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}

DYNAMIC_API PEP_STATUS get_phrase(
        PEP_SESSION session,
        const char *lang,
        int phrase_id,
        char **phrase
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (!(session && lang && lang[0] && lang[1] && lang[2] == 0 && phrase))
        return PEP_ILLEGAL_VALUE;

    *phrase = NULL;

    sqlite3_reset(session->i18n_token);
    sqlite3_bind_text(session->i18n_token, 1, lang, -1, SQLITE_STATIC);
    sqlite3_bind_int(session->i18n_token, 2, phrase_id);

    const char *_phrase = NULL;
    int result;

    result = sqlite3_step(session->i18n_token);
    switch (result) {
    case SQLITE_ROW:
        _phrase = (const char *) sqlite3_column_text(session->i18n_token, 0);
        break;

    case SQLITE_DONE:
        status = PEP_PHRASE_NOT_FOUND;
        break;

    default:
        status = PEP_UNKNOWN_DB_ERROR;
    }

    if (status == PEP_STATUS_OK) {
        *phrase = strdup(_phrase);
        if (*phrase == NULL)
            goto enomem;
    }

    sqlite3_reset(session->i18n_token);
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}

/**
 *  @internal
 *
 *  <!--       _get_sequence_value()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *name        const char
 *  @param[in]    *value        int32_t
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_RECORD_NOT_FOUND
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *
 */
static PEP_STATUS _get_sequence_value(PEP_SESSION session, const char *name,
        int32_t *value)
{
    if (!(session && name && value))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    sqlite3_reset(session->sequence_value2);
    sqlite3_bind_text(session->sequence_value2, 1, name, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->sequence_value2);
    switch (result) {
        case SQLITE_ROW: {
            int32_t _value = (int32_t)
                    sqlite3_column_int(session->sequence_value2, 0);
            *value = _value;
            break;
        }
        case SQLITE_DONE:
            status = PEP_RECORD_NOT_FOUND;
            break;
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    sqlite3_reset(session->sequence_value2);

    return status;
}

/**
 *  @internal
 *
 *  <!--       _increment_sequence_value()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *name        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_CANNOT_INCREASE_SEQUENCE
 *
 */
static PEP_STATUS _increment_sequence_value(PEP_SESSION session,
        const char *name)
{
    if (!(session && name))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->sequence_value1);
    sqlite3_bind_text(session->sequence_value1, 1, name, -1, SQLITE_STATIC);
    int result = sqlite3_step(session->sequence_value1);
    assert(result == SQLITE_DONE);
    sqlite3_reset(session->sequence_value1);
    if (result == SQLITE_DONE)
        return PEP_STATUS_OK;
    else
        return PEP_CANNOT_INCREASE_SEQUENCE;
}

DYNAMIC_API PEP_STATUS sequence_value(
        PEP_SESSION session,
        const char *name,
        int32_t *value
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (!(session && name && name[0] && value))
        return PEP_ILLEGAL_VALUE;

    *value = 0;
    sqlite3_exec(session->db, "BEGIN TRANSACTION ;", NULL, NULL, NULL);
    status = _increment_sequence_value(session, name);
    if (status == PEP_STATUS_OK)
        status = _get_sequence_value(session, name, value);

    if (status == PEP_STATUS_OK) {
        int result = sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
        if (result == SQLITE_OK){
            assert(*value < INT32_MAX);
            if (*value == INT32_MAX){
                return PEP_CANNOT_INCREASE_SEQUENCE;
            }
            return status;
        } else {
            return PEP_COMMIT_FAILED;
        }
    } else {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        return status;
    }

    return status;
}

PEP_STATUS is_own_key(PEP_SESSION session, const char* fpr, bool* own_key) {
    
    if (!session || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;
    
    *own_key = false;

    char* default_own_userid = NULL;
    pEp_identity* placeholder_ident = NULL;

    PEP_STATUS status = get_default_own_userid(session, &default_own_userid);

    if (status == PEP_STATUS_OK && !EMPTYSTR(default_own_userid)) {
        placeholder_ident = new_identity(NULL, fpr, default_own_userid, NULL);
        if (!placeholder_ident)
            status = PEP_OUT_OF_MEMORY;
        else
            status = get_trust(session, placeholder_ident);

        if (status == PEP_STATUS_OK) {
            if (placeholder_ident->comm_type == PEP_ct_pEp) {
                stringlist_t* keylist = NULL;
                status = find_private_keys(session, fpr, &keylist);
                if (status == PEP_STATUS_OK) {
                    if (keylist && !EMPTYSTR(keylist->value))
                        *own_key = true;
                }
                free_stringlist(keylist);
            }
        }
    }
    if (status == PEP_CANNOT_FIND_IDENTITY)
        status = PEP_STATUS_OK; // either no default own id yet, so no own keys yet
                                // or there was no own trust entry! False either way

    free(default_own_userid);
    free_identity(placeholder_ident);

    return status;
}

DYNAMIC_API PEP_STATUS set_revoked(
       PEP_SESSION session,
       const char *revoked_fpr,
       const char *replacement_fpr,
       const uint64_t revocation_date
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
        
    if (!(session &&
          revoked_fpr && revoked_fpr[0] &&
          replacement_fpr && replacement_fpr[0]
         ))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_reset(session->set_revoked);
    sqlite3_bind_text(session->set_revoked, 1, revoked_fpr, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->set_revoked, 2, replacement_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_int64(session->set_revoked, 3, revocation_date);

    int result;
    
    result = sqlite3_step(session->set_revoked);
    switch (result) {
        case SQLITE_DONE:
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    
    sqlite3_reset(session->set_revoked);
    return status;
}

DYNAMIC_API PEP_STATUS get_revoked(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
   
    if (!(session && revoked_fpr && fpr && fpr[0]))
        return PEP_ILLEGAL_VALUE;

    *revoked_fpr = NULL;
    *revocation_date = 0;

    sqlite3_reset(session->get_revoked);
    sqlite3_bind_text(session->get_revoked, 1, fpr, -1, SQLITE_STATIC);

    int result;
    
    result = sqlite3_step(session->get_revoked);
    switch (result) {
        case SQLITE_ROW: {
            *revoked_fpr = strdup((const char *)
                    sqlite3_column_text(session->get_revoked, 0));
            if(*revoked_fpr)
                *revocation_date = sqlite3_column_int64(session->get_revoked,
                        1);
            else
                status = PEP_OUT_OF_MEMORY;

            break;
        }
        default:
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->get_revoked);

    return status;
}

/**
 *  @internal
 *
 *  <!--       get_replacement_fpr()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle    
 *  @param[in]    *fpr                    const char
 *  @param[in]    **revoked_fpr            char
 *  @param[in]    *revocation_date        uint64_t
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *  @retval     PEP_OUT_OF_MEMORY           out of memory
 */
DYNAMIC_API PEP_STATUS get_replacement_fpr(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    if (!session || !revoked_fpr || EMPTYSTR(fpr) || !revocation_date)
        return PEP_ILLEGAL_VALUE;

    *revoked_fpr = NULL;
    *revocation_date = 0;

    sqlite3_reset(session->get_replacement_fpr);
    sqlite3_bind_text(session->get_replacement_fpr, 1, fpr, -1, SQLITE_STATIC);

    int result;
    
    result = sqlite3_step(session->get_replacement_fpr);
    switch (result) {
        case SQLITE_ROW: {
            *revoked_fpr = strdup((const char *)
                    sqlite3_column_text(session->get_replacement_fpr, 0));
            if(*revoked_fpr)
                *revocation_date = sqlite3_column_int64(session->get_replacement_fpr,
                        1);
            else
                status = PEP_OUT_OF_MEMORY;

            break;
        }
        default:
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->get_replacement_fpr);

    return status;
}

PEP_STATUS get_last_contacted(
        PEP_SESSION session,
        identity_list** id_list
    )
{
    if (!(session && id_list))
        return PEP_ILLEGAL_VALUE;

    *id_list = NULL;
    identity_list* ident_list = NULL;

    sqlite3_reset(session->get_last_contacted);
    int result;

    while ((result = sqlite3_step(session->get_last_contacted)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity(
                (const char *) sqlite3_column_text(session->get_last_contacted, 1),
                NULL,
                (const char *) sqlite3_column_text(session->get_last_contacted, 0),
                NULL);
                
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_last_contacted);
            return PEP_OUT_OF_MEMORY;
        }
    
        if (ident_list)
            identity_list_add(ident_list, ident);
        else
            ident_list = new_identity_list(ident);
    }

    sqlite3_reset(session->get_last_contacted);
    
    *id_list = ident_list;
    
    if (!ident_list)
        return PEP_CANNOT_FIND_IDENTITY;
    
    return PEP_STATUS_OK;    
}


PEP_STATUS key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    )
{
    if (!(session && fpr && created))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].key_created(session, fpr,
            created);
}

PEP_STATUS find_private_keys(PEP_SESSION session, const char* pattern,
                             stringlist_t **keylist) {
    if (!(session && keylist))
        return PEP_ILLEGAL_VALUE;
    
    return session->cryptotech[PEP_crypt_OpenPGP].find_private_keys(session, pattern,
                                                                    keylist);
}


DYNAMIC_API const char* get_engine_version() {
    return PEP_ENGINE_VERSION;
}

DYNAMIC_API const char* get_protocol_version() {
    return PEP_VERSION;
}

DYNAMIC_API PEP_STATUS reset_pEptest_hack(PEP_SESSION session)
{

    if (!session)
        return PEP_ILLEGAL_VALUE;

    int int_result = sqlite3_exec(
        session->db,
        "delete from identity where address like '%@pEptest.ch' ;",
        NULL,
        NULL,
        NULL
    );
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    return PEP_STATUS_OK;
}

DYNAMIC_API void _service_error_log(PEP_SESSION session, const char *entity,
        PEP_STATUS status, const char *where)
{
    char buffer[128];
    static const size_t size = 127;
    memset(buffer, 0, size+1);
#ifdef PEP_STATUS_TO_STRING
    snprintf(buffer, size, "%s %.4x", pEp_status_to_string(status), status);
#else
    snprintf(buffer, size, "error %.4x", status);
#endif
    log_service(session, "### service error log ###", entity, buffer, where);
}

DYNAMIC_API void set_debug_color(PEP_SESSION session, int ansi_color)
{
#ifndef NDEBUG
    session->debug_color = ansi_color;
#endif
}

PEP_STATUS set_all_userids_to_own(PEP_SESSION session, identity_list* id_list) {
    static char* ownid = NULL;
    PEP_STATUS status = PEP_STATUS_OK;
    if (!ownid) {
        status = get_default_own_userid(session, &ownid);
    }    
    if (status == PEP_STATUS_OK) {
        if (ownid) {
            status = set_all_userids_in_list(id_list, ownid);
        }
    }
    return status;    
}
