#include "pEp_internal.h"
#include "dynamic_api.h"
#include "cryptotech.h"
#include "transport.h"
#include "blacklist.h"

static int init_count = -1;

DYNAMIC_API PEP_STATUS init(PEP_SESSION *session)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int int_result;
    static const char *sql_log;
    static const char *sql_trustword;
    static const char *sql_get_identity;
    static const char *sql_set_person;
    static const char *sql_set_pgp_keypair;
    static const char *sql_set_identity;
    static const char *sql_set_trust;
    static const char *sql_get_trust;
    static const char *sql_least_trust;
    static const char *sql_mark_as_compromized;
    static const char *sql_crashdump;
    static const char *sql_languagelist;
    static const char *sql_i18n_token;

    // blacklist
    static const char *sql_blacklist_add;
    static const char *sql_blacklist_delete;
    static const char *sql_blacklist_is_listed;
    static const char *sql_blacklist_retrieve;

    // Own keys
    static const char *sql_own_key_is_listed;
    static const char *sql_own_key_retrieve;

    static const char *sql_sequence_value1;
    static const char *sql_sequence_value2;

    bool in_first = false;

    assert(sqlite3_threadsafe());
    if (!sqlite3_threadsafe())
        return PEP_INIT_SQLITE3_WITHOUT_MUTEX;

    // a little race condition - but still a race condition
    // mitigated by calling caveat (see documentation)

    ++init_count;
    if (init_count == 0)
        in_first = true;

    assert(session);
    if (session == NULL)
        return PEP_ILLEGAL_VALUE;

    *session = NULL;

    pEpSession *_session = calloc(1, sizeof(pEpSession));
    assert(_session);
    if (_session == NULL)
        goto enomem;

    _session->version = PEP_ENGINE_VERSION;

    assert(LOCAL_DB);
    if (LOCAL_DB == NULL) {
        status = PEP_INIT_CANNOT_OPEN_DB;
        goto pep_error;
    }

    int_result = sqlite3_open_v2(
            LOCAL_DB,
            &_session->db,
            SQLITE_OPEN_READWRITE
                | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_FULLMUTEX
                | SQLITE_OPEN_PRIVATECACHE,
            NULL 
        );

    if (int_result != SQLITE_OK) {
        status = PEP_INIT_CANNOT_OPEN_DB;
        goto pep_error;
    }

    sqlite3_busy_timeout(_session->db, BUSY_WAIT_TIME);

    assert(SYSTEM_DB);
    if (SYSTEM_DB == NULL) {
        status = PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
        goto pep_error;
    }

    int_result = sqlite3_open_v2(
            SYSTEM_DB, &_session->system_db,
            SQLITE_OPEN_READONLY
                | SQLITE_OPEN_FULLMUTEX
                | SQLITE_OPEN_SHAREDCACHE,
            NULL
        );

    if (int_result != SQLITE_OK) {
        status = PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
        goto pep_error;
    }

    sqlite3_busy_timeout(_session->system_db, 1000);

    if (in_first) {
        int_result = sqlite3_exec(
            _session->db,
                "create table if not exists version_info (\n"
                "   id integer primary key,\n"
                "   timestamp integer default (datetime('now')) ,\n"
                "   version text,\n"
                "   comment text\n"
                ");\n"
                "create table if not exists log (\n"
                "   timestamp integer default (datetime('now')) ,\n"
                "   title text not null,\n"
                "   entity text not null,\n"
                "   description text,\n"
                "   comment text\n"
                ");\n"
                "create index if not exists log_timestamp on log (\n"
                "   timestamp\n"
                ");\n"
                "create table if not exists pgp_keypair (\n"
                "   fpr text primary key,\n"
                "   public_id text unique,\n"
                "   private_id text,\n"
                "   created integer,\n"
                "   expires integer,\n"
                "   comment text\n"
                ");\n"
                "create index if not exists pgp_keypair_expires on pgp_keypair (\n"
                "   expires\n"
                ");\n"
                "create table if not exists person (\n"
                "   id text primary key,\n"
                "   username text not null,\n"
                "   main_key_id text\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete set null,\n"
                "   lang text,\n"
                "   comment text\n"
                ");\n"
                "create table if not exists identity (\n"
                "   address text,\n"
                "   user_id text\n"
                "       references person (id)\n"
                "       on delete cascade,\n"
                "   main_key_id text\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete set null,\n"
                "   comment text,\n"
                "   primary key (address, user_id)\n"
                ");\n"
                "create table if not exists trust (\n"
                "   user_id text not null\n"
                "       references person (id)\n"
                "       on delete cascade,\n"
                "   pgp_keypair_fpr text not null\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete cascade,\n"
                "   comm_type integer not null,\n"
                "   comment text\n"
                ");\n"
                "create unique index if not exists trust_index on trust (\n"
                "   user_id,\n"
                "   pgp_keypair_fpr\n"
                ");\n"
                // blacklist
                "create table if not exists blacklist_keys (\n"
                "   fpr text primary key\n"
                ");\n"
                // sequences
                "create table if not exists sequences(\n"
                "   name text primary key,\n"
                "   value integer default 0\n"
                ");\n"
                ,
            NULL,
            NULL,
            NULL
        );
        assert(int_result == SQLITE_OK);

        int_result = sqlite3_exec(
            _session->db,
            "insert or replace into version_info (id, version) values (1, '1.1');",
            NULL,
            NULL,
            NULL
        );
        assert(int_result == SQLITE_OK);

        sql_log = "insert into log (title, entity, description, comment)"
                  "values (?1, ?2, ?3, ?4);";

        sql_get_identity =  "select fpr, username, comm_type, lang"
                            "   from identity"
                            "   join person on id = identity.user_id"
                            "   join pgp_keypair on fpr = identity.main_key_id"
                            "   join trust on id = trust.user_id"
                            "       and pgp_keypair_fpr = identity.main_key_id"
                            "   where address = ?1 and identity.user_id = ?2;";

        sql_trustword = "select id, word from wordlist where lang = lower(?1) "
                       "and id = ?2 ;";

        // Set person, but if already exist, only update.
        // if main_key_id already set, don't touch.
        sql_set_person = "insert or replace into person (id, username, lang, main_key_id)"
                         "  values (?1, ?2, ?3,"
                         "    (select coalesce((select main_key_id from person "
                         "      where id = ?1), upper(replace(?4,' ',''))))) ;";

        sql_set_pgp_keypair = "insert or replace into pgp_keypair (fpr) "
                              "values (upper(replace(?1,' ',''))) ;";

        sql_set_identity = "insert or replace into identity (address, main_key_id, "
                           "user_id) values (?1, upper(replace(?2,' ','')), ?3) ;";

        sql_set_trust = "insert or replace into trust (user_id, pgp_keypair_fpr, comm_type) "
                        "values (?1, upper(replace(?2,' ','')), ?3) ;";

        sql_get_trust = "select comm_type from trust where user_id = ?1 "
                        "and pgp_keypair_fpr = upper(replace(?2,' ','')) ;";

        sql_least_trust = "select min(comm_type) from trust where pgp_keypair_fpr = upper(replace(?1,' ','')) ;";

        sql_mark_as_compromized = "update trust not indexed set comm_type = 15"
                                  " where pgp_keypair_fpr = upper(replace(?1,' ','')) ;";

        sql_crashdump = "select timestamp, title, entity, description, comment"
                        " from log order by timestamp desc limit ?1 ;";

        sql_languagelist = "select i18n_language.lang, name, phrase from i18n_language join i18n_token using (lang) where i18n_token.id = 1000;" ;

        sql_i18n_token = "select phrase from i18n_token where lang = lower(?1) and id = ?2 ;";

        // blacklist

        sql_blacklist_add = "insert or replace into blacklist_keys (fpr) values (upper(replace(?1,' ',''))) ;"
                            "delete from identity where main_key_id = upper(replace(?1,' ','')) ;"
                            "delete from pgp_keypair where fpr = upper(replace(?1,' ','')) ;";

        sql_blacklist_delete = "delete from blacklist_keys where fpr = upper(replace(?1,' ','')) ;";

        sql_blacklist_is_listed = "select count(*) from blacklist_keys where fpr = upper(replace(?1,' ','')) ;";

        sql_blacklist_retrieve = "select * from blacklist_keys ;";
        
        // Own keys
        
        sql_own_key_is_listed =
                                "select count(*) from ("
                                " select main_key_id from person "
                                "   where main_key_id = upper(replace(?1,' ',''))"
                                "    and id = '" PEP_OWN_USERID "' "
                                " union "
                                "  select main_key_id from identity "
                                "   where main_key_id = upper(replace(?1,' ',''))"
                                "    and user_id = '" PEP_OWN_USERID "' );";

        sql_own_key_retrieve = "select main_key_id from person "
                               "  where main_key_id is not null"
                               "   and id = '" PEP_OWN_USERID "' "
                               "union "
                               " select main_key_id from identity "
                               "  where main_key_id is not null"
                               "   and user_id = '" PEP_OWN_USERID "' ;";
        
        sql_sequence_value1 = "insert or replace into sequences (name, value) "
                              "values (?1, "
                              "(select coalesce((select value + 1 from sequences "
                              "where name = ?1), 1 ))) ; ";
        sql_sequence_value2 = "select value from sequences where name = ?1 ;";
    }

    int_result = sqlite3_prepare_v2(_session->db, sql_log, (int)strlen(sql_log),
            &_session->log, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->system_db, sql_trustword,
            (int)strlen(sql_trustword), &_session->trustword, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_get_identity,
            (int)strlen(sql_get_identity), &_session->get_identity, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_person,
            (int)strlen(sql_set_person), &_session->set_person, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_pgp_keypair,
            (int)strlen(sql_set_pgp_keypair), &_session->set_pgp_keypair, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_identity,
            (int)strlen(sql_set_identity), &_session->set_identity, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_trust,
            (int)strlen(sql_set_trust), &_session->set_trust, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_get_trust,
            (int)strlen(sql_get_trust), &_session->get_trust, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_least_trust,
            (int)strlen(sql_least_trust), &_session->least_trust, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_mark_as_compromized,
            (int)strlen(sql_mark_as_compromized), &_session->mark_compromized, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_crashdump,
            (int)strlen(sql_crashdump), &_session->crashdump, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->system_db, sql_languagelist,
            (int)strlen(sql_languagelist), &_session->languagelist, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->system_db, sql_i18n_token,
            (int)strlen(sql_i18n_token), &_session->i18n_token, NULL);
    assert(int_result == SQLITE_OK);

    // blacklist

    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_add,
            (int)strlen(sql_blacklist_add), &_session->blacklist_add, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_delete,
            (int)strlen(sql_blacklist_delete), &_session->blacklist_delete, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_is_listed,
            (int)strlen(sql_blacklist_is_listed), &_session->blacklist_is_listed, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_retrieve,
            (int)strlen(sql_blacklist_retrieve), &_session->blacklist_retrieve, NULL);
    assert(int_result == SQLITE_OK);

    // Own keys
    
    int_result = sqlite3_prepare_v2(_session->db, sql_own_key_is_listed,
            (int)strlen(sql_own_key_is_listed), &_session->own_key_is_listed, NULL);
    assert(int_result == SQLITE_OK);
    
    int_result = sqlite3_prepare_v2(_session->db, sql_own_key_retrieve,
            (int)strlen(sql_own_key_retrieve), &_session->own_key_retrieve, NULL);
    assert(int_result == SQLITE_OK);
 
    // Sequence

    int_result = sqlite3_prepare_v2(_session->db, sql_sequence_value1,
            (int)strlen(sql_sequence_value1), &_session->sequence_value1, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_sequence_value2,
            (int)strlen(sql_sequence_value2), &_session->sequence_value2, NULL);
    assert(int_result == SQLITE_OK);

    status = init_cryptotech(_session, in_first);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    status = init_transport_system(_session, in_first);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    status = log_event(_session, "init", "pEp " PEP_ENGINE_VERSION, NULL, NULL);
    if (status != PEP_STATUS_OK)
        goto pep_error;

    // runtime config

    _session->passive_mode = false;
    _session->unencrypted_subject = false;

    *session = _session;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pep_error:
    release(_session);
    return status;
}

DYNAMIC_API void release(PEP_SESSION session)
{
    bool out_last = false;

    assert(init_count >= 0);
    assert(session);

    if (!((init_count >= 0) && session))
        return;

    // a small race condition but still a race condition
    // mitigated by calling caveat (see documentation)

    if (init_count == 0)
        out_last = true;
    --init_count;

    if (session) {
        if (session->db) {
            if (session->log)
                sqlite3_finalize(session->log);
            if (session->trustword)
                sqlite3_finalize(session->trustword);
            if (session->get_identity)
                sqlite3_finalize(session->get_identity);
            if (session->set_person)
                sqlite3_finalize(session->set_person);
            if (session->set_pgp_keypair)
                sqlite3_finalize(session->set_pgp_keypair);
            if (session->set_identity)
                sqlite3_finalize(session->set_identity);
            if (session->set_trust)
                sqlite3_finalize(session->set_trust);
            if (session->get_trust)
                sqlite3_finalize(session->get_trust);
            if (session->least_trust)
                sqlite3_finalize(session->least_trust);
            if (session->mark_compromized)
                sqlite3_finalize(session->mark_compromized);
            if (session->crashdump)
                sqlite3_finalize(session->crashdump);
            if (session->languagelist)
                sqlite3_finalize(session->languagelist);
            if (session->i18n_token)
                sqlite3_finalize(session->i18n_token);
            if (session->blacklist_add)
                sqlite3_finalize(session->blacklist_add);
            if (session->blacklist_delete)
                sqlite3_finalize(session->blacklist_delete);
            if (session->blacklist_is_listed)
                sqlite3_finalize(session->blacklist_is_listed);
            if (session->blacklist_retrieve)
                sqlite3_finalize(session->blacklist_retrieve);

            if (session->db)
                sqlite3_close_v2(session->db);
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
    session->passive_mode = enable;
}

DYNAMIC_API void config_unencrypted_subject(PEP_SESSION session, bool enable)
{
    assert(session);
    session->unencrypted_subject = enable;
}

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session,
        const char *title,
        const char *entity,
        const char *description,
        const char *comment
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    assert(session);
    assert(title);
    assert(entity);

    if (!(session && title && entity))
        return PEP_ILLEGAL_VALUE;

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
    do {
        result = sqlite3_step(session->log);
        assert(result == SQLITE_DONE || result == SQLITE_BUSY);
        if (result != SQLITE_DONE && result != SQLITE_BUSY)
            status = PEP_UNKNOWN_ERROR;
    } while (result == SQLITE_BUSY);
    sqlite3_reset(session->log);

    return status;
}

DYNAMIC_API PEP_STATUS trustword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    assert(session);
    assert(word);
    assert(wsize);

    if (!(session && word && wsize))
        return PEP_ILLEGAL_VALUE;

    *word = NULL;
    *wsize = 0;

    if (lang == NULL)
        lang = "en";

    assert((lang[0] >= 'A' && lang[0] <= 'Z')
            || (lang[0] >= 'a' && lang[0] <= 'z'));
    assert((lang[1] >= 'A' && lang[1] <= 'Z')
            || (lang[1] >= 'a' && lang[1] <= 'z'));
    assert(lang[2] == 0);

    sqlite3_reset(session->trustword);
    sqlite3_bind_text(session->trustword, 1, lang, -1, SQLITE_STATIC);
    sqlite3_bind_int(session->trustword, 2, value);

    result = sqlite3_step(session->trustword);
    if (result == SQLITE_ROW) {
        *word = strdup((const char *) sqlite3_column_text(session->trustword,
                    1));
        if (*word)
            *wsize = sqlite3_column_bytes(session->trustword, 1);
        else
            status = PEP_TRUSTWORD_NOT_FOUND;
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
    char *buffer;
    char *dest;
    size_t fsize;
    PEP_STATUS _status;

    assert(session);
    assert(fingerprint);
    assert(words);
    assert(wsize);
    assert(max_words >= 0);

    if (!(session && fingerprint && words && wsize && max_words >= 0))
        return PEP_ILLEGAL_VALUE;

    *words = NULL;
    *wsize = 0;

    buffer = calloc(1, MAX_TRUSTWORDS_SPACE);
    assert(buffer);
    if (buffer == NULL)
        return PEP_OUT_OF_MEMORY;
    dest = buffer;

    fsize = strlen(fingerprint);

    if (!lang || !lang[0])
        lang = "en";

    assert((lang[0] >= 'A' && lang[0] <= 'Z')
            || (lang[0] >= 'a' && lang[0] <= 'z'));
    assert((lang[1] >= 'A' && lang[1] <= 'Z')
            || (lang[1] >= 'a' && lang[1] <= 'z'));
    assert(lang[2] == 0);

    int n_words = 0;
    while (source < fingerprint + fsize) {
        uint16_t value;
        char *word;
        size_t _wsize;
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

        if (source < fingerprint + fsize
                && dest + _wsize < buffer + MAX_TRUSTWORDS_SPACE - 1)
            *dest++ = ' ';

        ++n_words;
        if (max_words && n_words >= max_words)
            break;
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
    assert(result);
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
    assert(src);

    pEp_identity *dup = new_identity(src->address, src->fpr, src->user_id, src->username);
    assert(dup);
    if (dup == NULL)
        return NULL;
    
    dup->comm_type = src->comm_type;
    dup->lang[0] = src->lang[0];
    dup->lang[1] = src->lang[1];
    dup->lang[2] = 0;
    dup->me = src->me;

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

DYNAMIC_API PEP_STATUS get_identity(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    static pEp_identity *_identity;
    int result;
    const char *_lang;

    assert(session);
    assert(address);
    assert(address[0]);
    assert(identity);

    if (!(session && address && address[0] && identity))
        return PEP_ILLEGAL_VALUE;

    *identity = NULL;

    sqlite3_reset(session->get_identity);
    sqlite3_bind_text(session->get_identity, 1, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_identity, 2, user_id, -1, SQLITE_STATIC);

    result = sqlite3_step(session->get_identity);
    switch (result) {
    case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identity, 0),
                user_id,
                (const char *) sqlite3_column_text(session->get_identity, 1)
                );
        assert(_identity);
        if (_identity == NULL)
            return PEP_OUT_OF_MEMORY;

        _identity->comm_type = (PEP_comm_type) sqlite3_column_int(session->get_identity, 2);
        _lang = (const char *) sqlite3_column_text(session->get_identity, 3);
        if (_lang && _lang[0]) {
            assert(_lang[0] >= 'a' && _lang[0] <= 'z');
            assert(_lang[1] >= 'a' && _lang[1] <= 'z');
            assert(_lang[2] == 0);
            _identity->lang[0] = _lang[0];
            _identity->lang[1] = _lang[1];
            _identity->lang[2] = 0;
        }
        *identity = _identity;
        break;
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
        *identity = NULL;
    }

    sqlite3_reset(session->get_identity);
    return status;
}

DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    int result;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr);
    assert(identity->user_id);
    assert(identity->username);

    if (!(session && identity && identity->address && identity->fpr &&
                identity->user_id && identity->username))
        return PEP_ILLEGAL_VALUE;

    bool listed;
    PEP_STATUS status = blacklist_is_listed(session, identity->fpr, &listed);
    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;

    if (listed)
        return PEP_KEY_BLACKLISTED;

    sqlite3_exec(session->db, "BEGIN ;", NULL, NULL, NULL);

    sqlite3_reset(session->set_person);
    sqlite3_bind_text(session->set_person, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_person, 2, identity->username, -1,
            SQLITE_STATIC);
    if (identity->lang[0])
        sqlite3_bind_text(session->set_person, 3, identity->lang, 1,
                SQLITE_STATIC);
    else
        sqlite3_bind_null(session->set_person, 3);
    sqlite3_bind_text(session->set_person, 4, identity->fpr, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->set_person);
    sqlite3_reset(session->set_person);
    if (result != SQLITE_DONE) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        return PEP_CANNOT_SET_PERSON;
    }

    sqlite3_reset(session->set_pgp_keypair);
    sqlite3_bind_text(session->set_pgp_keypair, 1, identity->fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->set_pgp_keypair);
    sqlite3_reset(session->set_pgp_keypair);
    if (result != SQLITE_DONE) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        return PEP_CANNOT_SET_PGP_KEYPAIR;
    }

    sqlite3_reset(session->set_identity);
    sqlite3_bind_text(session->set_identity, 1, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_identity, 2, identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_identity, 3, identity->user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->set_identity);
    sqlite3_reset(session->set_identity);
    if (result != SQLITE_DONE) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        return PEP_CANNOT_SET_IDENTITY;
    }

    sqlite3_reset(session->set_trust);
    sqlite3_bind_text(session->set_trust, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_trust, 2, identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_int(session->set_trust, 3, identity->comm_type);
    result = sqlite3_step(session->set_trust);
    sqlite3_reset(session->set_trust);
    if (result != SQLITE_DONE) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        return PEP_CANNOT_SET_TRUST;
    }

    result = sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
    if (result == SQLITE_OK)
        return PEP_STATUS_OK;
    else
        return PEP_COMMIT_FAILED;
}

DYNAMIC_API PEP_STATUS mark_as_compromized(
        PEP_SESSION session,
        const char *fpr
    )
{
    int result;

    assert(session);
    assert(fpr && fpr[0]);

    if (!(session && fpr && fpr[0]))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->mark_compromized);
    sqlite3_bind_text(session->mark_compromized, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->mark_compromized);
    sqlite3_reset(session->mark_compromized);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    return PEP_STATUS_OK;
}

void pEp_free(void *p)
{
    free(p);
}

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    assert(session);
    assert(identity);
    assert(identity->user_id);
    assert(identity->user_id[0]);
    assert(identity->fpr);
    assert(identity->fpr[0]);

    if (!(session && identity && identity->user_id && identity->user_id[0] &&
                identity->fpr && identity->fpr[0]))
        return PEP_ILLEGAL_VALUE;

    identity->comm_type = PEP_ct_unknown;

    sqlite3_reset(session->get_trust);
    sqlite3_bind_text(session->get_trust, 1, identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_trust, 2, identity->fpr, -1, SQLITE_STATIC);

    result = sqlite3_step(session->get_trust);
    switch (result) {
    case SQLITE_ROW: {
        int comm_type = (PEP_comm_type) sqlite3_column_int(session->get_trust, 0);
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

    assert(session);
    assert(fpr);
    assert(comm_type);

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
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->least_trust);
    return status;
}

DYNAMIC_API PEP_STATUS decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    char **ptext, size_t *psize, stringlist_t **keylist
    )
{
    assert(session);
    assert(ctext);
    assert(csize);
    assert(ptext);
    assert(psize);
    assert(keylist);

    if (!(session && ctext && csize && ptext && psize && keylist && keylist))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].decrypt_and_verify(session, ctext, csize, ptext, psize, keylist);
}

DYNAMIC_API PEP_STATUS encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    assert(session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    if (!(session && keylist && ptext && psize && ctext && csize))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].encrypt_and_sign(session, keylist, ptext, psize, ctext, csize);
}

DYNAMIC_API PEP_STATUS verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    assert(session);
    assert(text);
    assert(size);
    assert(signature);
    assert(sig_size);
    assert(keylist);

    if (!(session && text && size && signature && sig_size && keylist))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].verify_text(session, text, size, signature, sig_size, keylist);
}

DYNAMIC_API PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr)
{
    assert(session);
    assert(fpr);

    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].delete_keypair(session, fpr);
}

DYNAMIC_API PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    assert(session);
    assert(fpr);
    assert(key_data);
    assert(size);

    if (!(session && fpr && key_data && size))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].export_key(session, fpr, key_data, size);
}

DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    assert(session);
    assert(pattern);
    assert(keylist);

    if (!(session && pattern && keylist))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].find_keys(session, pattern, keylist);
}

DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    )
{
    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL || identity->fpr[0] == 0);
    assert(identity->username);

    if (!(session && identity && identity->address &&
        (identity->fpr == NULL || identity->fpr[0] == 0) && identity->username))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].generate_keypair(session, identity);
}

DYNAMIC_API PEP_STATUS get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    )
{
    assert(session);
    assert(fpr);
    assert(comm_type);

    if (!(session && fpr && comm_type))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].get_key_rating(session, fpr, comm_type);
}

DYNAMIC_API PEP_STATUS import_key(PEP_SESSION session, const char *key_data, size_t size)
{
    assert(session);
    assert(key_data);

    if (!(session && key_data))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].import_key(session, key_data, size);
}

DYNAMIC_API PEP_STATUS recv_key(PEP_SESSION session, const char *pattern)
{
    assert(session);
    assert(pattern);

    if (!(session && pattern))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].recv_key(session, pattern);
}

DYNAMIC_API PEP_STATUS send_key(PEP_SESSION session, const char *pattern)
{
    assert(session);
    assert(pattern);

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
    assert(session);
    assert(fpr);

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
    assert(session);
    assert(fpr);

    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].revoke_key(session, fpr,
            reason);
}

DYNAMIC_API PEP_STATUS key_expired(
        PEP_SESSION session,
        const char *fpr,
        bool *expired
    )
{
    assert(session);
    assert(fpr);
    assert(expired);

    if (!(session && fpr && expired))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].key_expired(session, fpr,
            expired);
}

static void _clean_log_value(char *text)
{
    if (text) {
        for (char *c = text; *c; c++) {
            if (*c < 32)
                *c = 32;
            else if (*c == '"')
                *c = '\'';
        }
    }
}

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
        _clean_log_value(result + len1 + 1);
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

    assert(session);
    assert(maxlines >= 0 && maxlines <= CRASHDUMP_MAX_LINES);
    assert(logdata);

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
            timestamp = (const char *) sqlite3_column_text(session->crashdump, 0);
            title   = (const char *) sqlite3_column_text(session->crashdump, 1);
            entity  = (const char *) sqlite3_column_text(session->crashdump, 2);
            desc    = (const char *) sqlite3_column_text(session->crashdump, 3);
            comment = (const char *) sqlite3_column_text(session->crashdump, 4);

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

            break;

        case SQLITE_DONE:
            break;

        default:
            status = PEP_UNKNOWN_ERROR;
            result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);

    sqlite3_reset(session->crashdump);
    if (status == PEP_STATUS_OK)
        *logdata = _logdata;

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

    assert(session);
    assert(languages);

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
            lang = (const char *) sqlite3_column_text(session->languagelist, 0);
            name = (const char *) sqlite3_column_text(session->languagelist, 1);
            phrase = (const char *) sqlite3_column_text(session->languagelist, 2);

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
            status = PEP_UNKNOWN_ERROR;
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

    assert(session && lang && lang[0] && lang[1] && lang[2] == 0 && phrase);
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
        status = PEP_UNKNOWN_ERROR;
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

DYNAMIC_API PEP_STATUS sequence_value(
        PEP_SESSION session,
        const char *name,
        int32_t *value
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    assert(session);
    assert(name);
    assert(value);

    if (!(session && name && value))
        return PEP_ILLEGAL_VALUE;

    *value = 0;

    sqlite3_reset(session->sequence_value1);
    sqlite3_bind_text(session->sequence_value1, 1, name, -1, SQLITE_STATIC);
    result = sqlite3_step(session->sequence_value1);
    assert(result == SQLITE_DONE);
    sqlite3_reset(session->sequence_value1);
    if (result != SQLITE_DONE) {
        status = PEP_UNKNOWN_ERROR;
    }
    else {
        sqlite3_reset(session->sequence_value2);
        sqlite3_bind_text(session->sequence_value2, 1, name, -1, SQLITE_STATIC);
        result = sqlite3_step(session->sequence_value2);
        switch (result) {
            case SQLITE_ROW: {
                int32_t _value = (int32_t)
                        sqlite3_column_int64(session->sequence_value2, 0);
                *value = _value;
                break;
            }
            default:
                status = PEP_UNKNOWN_ERROR;
        }
        sqlite3_reset(session->sequence_value2);
    }
    return status;
}

DYNAMIC_API PEP_STATUS reset_peptest_hack(PEP_SESSION session)
{
    assert(session);

    if (!session)
        return PEP_ILLEGAL_VALUE;

    int int_result = sqlite3_exec(
        session->db,
        "delete from identity where address like '%@peptest.ch' ;",
        NULL,
        NULL,
        NULL
    );
    assert(int_result == SQLITE_OK);

    return PEP_STATUS_OK;
}

