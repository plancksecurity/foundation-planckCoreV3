#include "dynamic_api.h"
#include "pEp_internal.h"
#include "cryptotech.h"
#include "transport.h"

int init_count = -1;

DYNAMIC_API PEP_STATUS init(PEP_SESSION *session)
{
    PEP_STATUS status = PEP_STATUS_OK;
	int int_result;
	static const char *sql_log;
	static const char *sql_safeword;
	static const char *sql_get_identity;
	static const char *sql_set_person;
	static const char *sql_set_pgp_keypair;
	static const char *sql_set_identity;
	static const char *sql_set_trust;
    static const char *sql_get_trust;
    bool in_first = false;

    assert(sqlite3_threadsafe());
    if (!sqlite3_threadsafe())
        return PEP_INIT_SQLITE3_WITHOUT_MUTEX;

    // a little race condition - but still a race condition
    // removed by calling caveat (see documentation)

    ++init_count;
    if (init_count == 0)
        in_first = true;

	assert(session);
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
                "create table if not exists version_info ("
                "	id integer primary key,"
                "	timestamp integer default (datetime('now')) ,"
                "	version text,"
                "	comment text"
                ");"
                "create table if not exists log ("
                "	timestamp integer default (datetime('now')) ,"
                "	title text not null,"
                "	entity text not null,"
                "	description text,"
                "	comment text"
                ");"
                "create index if not exists log_timestamp on log ("
                "	timestamp"
                ");"
                "create table if not exists pgp_keypair ("
                "	fpr text primary key,"
                "	public_id text unique,"
                "   private_id text,"
                "	created integer,"
                "	expires integer,"
                "	comment text"
                ");"
                "create index if not exists pgp_keypair_expires on pgp_keypair ("
                "	expires"
                ");"
                "create table if not exists person ("
                "	id text primary key,"
                "	username text not null,"
                "	main_key_id text"
                "		references pgp_keypair (fpr)"
                "		on delete set null,"
                "   lang text,"
                "	comment text"
                ");"
                "create table if not exists identity ("
                "	address text primary key,"
                "	user_id text"
                "		references person (id)"
                "		on delete cascade,"
                "	main_key_id text"
                "		references pgp_keypair (fpr)"
                "		on delete set null,"
                "	comment text"
                ");"
                "create table if not exists trust ("
                "   user_id text not null"
                "       references person (id)"
                "		on delete cascade,"
                "   pgp_keypair_fpr text not null"
                "       references pgp_keypair (fpr)"
                "       on delete cascade,"
                "   comm_type integer not null,"
                "	comment text"
                ");"
                "create unique index if not exists trust_index on trust ("
                "   user_id,"
                "   pgp_keypair_fpr"
                ");",
            NULL,
            NULL,
            NULL
        );
        assert(int_result == SQLITE_OK);

        int_result = sqlite3_exec(
            _session->db,
            "insert or replace into version_info (id, version) values (1, '1.0');",
            NULL,
            NULL,
            NULL
        );
        assert(int_result == SQLITE_OK);

        sql_log = "insert into log (title, entity, description, comment)"
                  "values (?1, ?2, ?3, ?4);";

        sql_get_identity =	"select fpr, identity.user_id, username, comm_type, lang"
                            "   from identity"
                            "   join person on id = identity.user_id"
                            "   join pgp_keypair on fpr = identity.main_key_id"
                            "   join trust on id = trust.user_id"
                            "       and pgp_keypair_fpr = identity.main_key_id"
                            "   where address = ?1 ;";

        sql_safeword = "select id, word from wordlist where lang = lower(?1) "
                       "and id = ?2 ;";

        sql_set_person = "insert or replace into person (id, username, lang) "
                         "values (?1, ?2, ?3) ;";

        sql_set_pgp_keypair = "insert or replace into pgp_keypair (fpr) "
                              "values (?1) ;";

        sql_set_identity = "insert or replace into identity (address, main_key_id, "
                           "user_id) values (?1, ?2, ?3) ;";

        sql_set_trust = "insert or replace into trust (user_id, pgp_keypair_fpr, comm_type) "
                        "values (?1, ?2, ?3) ;";

        sql_get_trust = "select user_id, comm_type from trust where user_id = ?1 "
                        "and pgp_keypair_fpr = ?2 ;";
    }

    int_result = sqlite3_prepare_v2(_session->db, sql_log, strlen(sql_log),
            &_session->log, NULL);
	assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->system_db, sql_safeword,
            strlen(sql_safeword), &_session->safeword, NULL);
	assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_get_identity,
            strlen(sql_get_identity), &_session->get_identity, NULL);
	assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_person,
            strlen(sql_set_person), &_session->set_person, NULL);
    assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_pgp_keypair,
            strlen(sql_set_pgp_keypair), &_session->set_pgp_keypair, NULL);
	assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_identity,
            strlen(sql_set_identity), &_session->set_identity, NULL);
	assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_set_trust,
            strlen(sql_set_trust), &_session->set_trust, NULL);
	assert(int_result == SQLITE_OK);

    int_result = sqlite3_prepare_v2(_session->db, sql_get_trust,
            strlen(sql_get_trust), &_session->get_trust, NULL);
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

    // a small race condition but still a race condition
    // removed by calling caveat (see documentation)

    if (init_count == 0)
        out_last = true;
    --init_count;

	if (session) {
		if (session->db) {
            if (session->safeword)
                sqlite3_finalize(session->safeword);
            if (session->log)
                sqlite3_finalize(session->log);
            if (session->get_identity)
                sqlite3_finalize(session->get_identity);
            if (session->set_identity)
                sqlite3_finalize(session->set_identity);
            if (session->set_person)
                sqlite3_finalize(session->set_person);
            if (session->set_pgp_keypair)
                sqlite3_finalize(session->set_pgp_keypair);
            if (session->set_trust)
                sqlite3_finalize(session->set_trust);
            if (session->get_trust)
                sqlite3_finalize(session->get_trust);

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

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session, const char *title, const char *entity,
        const char *description, const char *comment
    )
{
	PEP_STATUS status = PEP_STATUS_OK;
	int result;

	assert(session);
	assert(title);
	assert(entity);

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

DYNAMIC_API PEP_STATUS safeword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        )
{
	PEP_STATUS status = PEP_STATUS_OK;
	int result;

	assert(session);
	assert(word);
	assert(wsize);

	*word = NULL;
	*wsize = 0;

	if (lang == NULL)
		lang = "en";

	assert((lang[0] >= 'A' && lang[0] <= 'Z')
            || (lang[0] >= 'a' && lang[0] <= 'z'));
	assert((lang[1] >= 'A' && lang[1] <= 'Z')
            || (lang[1] >= 'a' && lang[1] <= 'z'));
	assert(lang[2] == 0);

	sqlite3_reset(session->safeword);
    sqlite3_bind_text(session->safeword, 1, lang, -1, SQLITE_STATIC);
	sqlite3_bind_int(session->safeword, 2, value);

	result = sqlite3_step(session->safeword);
	if (result == SQLITE_ROW) {
        *word = strdup((const char *) sqlite3_column_text(session->safeword,
                    1));
		if (*word)
            *wsize = sqlite3_column_bytes(session->safeword, 1);
		else
			status = PEP_SAFEWORD_NOT_FOUND;
	} else
		status = PEP_SAFEWORD_NOT_FOUND;

	sqlite3_reset(session->safeword);
	return status;
}

DYNAMIC_API PEP_STATUS safewords(
        PEP_SESSION session, const char *fingerprint, const char *lang,
        char **words, size_t *wsize, int max_words
    )
{
	const char *source = fingerprint;
	char *buffer;
	char *dest = buffer;
	size_t fsize;
    PEP_STATUS _status;

	assert(session);
	assert(fingerprint);
	assert(words);
	assert(wsize);
	assert(max_words >= 0);

	*words = NULL;
	*wsize = 0;

    buffer = calloc(1, MAX_SAFEWORDS_SPACE);
    assert(buffer);
    if (buffer == NULL)
        return PEP_OUT_OF_MEMORY;

	fsize = strlen(fingerprint);

	if (lang == NULL)
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

		_status = safeword(session, value, lang, &word, &_wsize);
        if (_status == PEP_OUT_OF_MEMORY) {
            free(buffer);
            return PEP_OUT_OF_MEMORY;
        }
		if (word == NULL) {
            free(buffer);
			return PEP_SAFEWORD_NOT_FOUND;
        }

		if (dest + _wsize < buffer + MAX_SAFEWORDS_SPACE - 1) {
			strncpy(dest, word, _wsize);
            free(word);
			dest += _wsize;
		}
		else {
            free(word);
			break; // buffer full
        }

		if (source < fingerprint + fsize
                && dest + _wsize < buffer + MAX_SAFEWORDS_SPACE - 1)
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
            result->address_size = strlen(address);
        }
        if (fpr) {
            result->fpr = strdup(fpr);
            assert(result->fpr);
            if (result->fpr == NULL) {
                free_identity(result);
                return NULL;
            }
            result->fpr_size = strlen(fpr);
        }
        if (user_id) {
            result->user_id = strdup(user_id);
            assert(result->user_id);
            if (result->user_id == NULL) {
                free_identity(result);
                return NULL;
            }
            result->user_id_size = strlen(user_id);
        }
        if (username) {
            result->username = strdup(username);
            assert(result->username);
            if (result->username == NULL) {
                free_identity(result);
                return NULL;
            }
            result->username_size = strlen(username);
        }
        result->struct_size = sizeof(pEp_identity);
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
        PEP_SESSION session, const char *address,
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

    sqlite3_reset(session->get_identity);
    sqlite3_bind_text(session->get_identity, 1, address, -1, SQLITE_STATIC);

    result = sqlite3_step(session->get_identity);
	switch (result) {
	case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identity, 0),
                (const char *) sqlite3_column_text(session->get_identity, 1),
                (const char *) sqlite3_column_text(session->get_identity, 2)
                );
        assert(_identity);
        if (_identity == NULL)
            return PEP_OUT_OF_MEMORY;

        _identity->comm_type = (PEP_comm_type) sqlite3_column_int(session->get_identity, 3);
        _lang = (const char *) sqlite3_column_text(session->get_identity, 4);
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
		return PEP_CANNOT_SET_IDENTITY;
	}

    result = sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);
	if (result == SQLITE_OK)
		return PEP_STATUS_OK;
	else
		return PEP_COMMIT_FAILED;
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

    identity->comm_type = PEP_ct_unknown;

    sqlite3_reset(session->get_trust);
    sqlite3_bind_text(session->get_trust, 1, identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_trust, 2, identity->fpr, -1, SQLITE_STATIC);

    result = sqlite3_step(session->get_trust);
    switch (result) {
    case SQLITE_ROW: {
        const char * user_id = (const char *) sqlite3_column_text(session->get_trust, 1);
        int comm_type = (PEP_comm_type) sqlite3_column_int(session->get_trust, 2);

        if (strcmp(user_id, identity->user_id) != 0) {
            free(identity->user_id);
            identity->user_id = strdup(user_id);
            assert(identity->user_id);
            if (identity->user_id == NULL)
                return PEP_OUT_OF_MEMORY;
        }
        identity->comm_type = comm_type;
        break;
    }
 
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
    }

    sqlite3_reset(session->get_trust);
    return status;
}

DYNAMIC_API PEP_STATUS decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    char **ptext, size_t *psize, stringlist_t **keylist
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].decrypt_and_verify(session, ctext, csize, ptext, psize, keylist);
}

DYNAMIC_API PEP_STATUS encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].encrypt_and_sign(session, keylist, ptext, psize, ctext, csize);
}

DYNAMIC_API PEP_STATUS verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].verify_text(session, text, size, signature, sig_size, keylist);
}

DYNAMIC_API PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr)
{
    return session->cryptotech[PEP_crypt_OpenPGP].delete_keypair(session, fpr);
}

DYNAMIC_API PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].export_key(session, fpr, key_data, size);
}

DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].find_keys(session, pattern, keylist);
}

DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].generate_keypair(session, identity);
}

DYNAMIC_API PEP_STATUS get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    )
{
    return session->cryptotech[PEP_crypt_OpenPGP].get_key_rating(session, fpr, comm_type);
}

DYNAMIC_API PEP_STATUS import_key(PEP_SESSION session, const char *key_data, size_t size)
{
    return session->cryptotech[PEP_crypt_OpenPGP].import_key(session, key_data, size);
}

DYNAMIC_API PEP_STATUS recv_key(PEP_SESSION session, const char *pattern)
{
    return session->cryptotech[PEP_crypt_OpenPGP].recv_key(session, pattern);
}

DYNAMIC_API PEP_STATUS send_key(PEP_SESSION session, const char *pattern)
{
    return session->cryptotech[PEP_crypt_OpenPGP].send_key(session, pattern);
}
