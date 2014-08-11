#define PEP_ENGINE_VERSION "0.4.0"

// this is 20 safewords with 79 chars max
#define MAX_SAFEWORDS_SPACE (20 * 80)

// XML parameters string
#define PARMS_MAX 32768

// maximum busy wait time in ms
#define BUSY_WAIT_TIME 5000

// maximum line length for reading gpg.conf
#define MAX_LINELENGTH 1024

// default keyserver
#define DEFAULT_KEYSERVER "hkp://keys.gnupg.net"

#ifdef WIN32
#include "platform_windows.h"
#define LOCAL_DB windoze_local_db()
#define SYSTEM_DB windoze_system_db()
#define LIBGPGME "libgpgme-11.dll"
#else // UNIX
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include "platform_unix.h"
#define LOCAL_DB unix_local_db()
#ifndef SYSTEM_DB
#define SYSTEM_DB "/usr/share/pEp/system.db"
#endif
#ifndef LIBGPGME
#define LIBGPGME "libgpgme-pthread.so"
#endif
#endif

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#ifndef NDEBUG
#include <stdio.h>
#endif

#include <gpgme.h>
#include "sqlite3.h"

#define _EXPORT_PEP_ENGINE_DLL
#include "pEpEngine.h"

#define NOT_IMPLEMENTED assert(0)

// init

typedef const char * (*gpgme_check_version_t)(const char*);
typedef gpgme_error_t (*gpgme_set_locale_t)(gpgme_ctx_t CTX, int CATEGORY,
        const char *VALUE);
typedef gpgme_error_t (*gpgme_new_t)(gpgme_ctx_t *CTX);
typedef void (*gpgme_release_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t (*gpgme_set_protocol_t)(gpgme_ctx_t CTX,
        gpgme_protocol_t PROTO);
typedef void (*gpgme_set_armor_t)(gpgme_ctx_t CTX, int YES);

// data

typedef gpgme_error_t (*gpgme_data_new_t)(gpgme_data_t *DH);
typedef gpgme_error_t (*gpgme_data_new_from_mem_t)(gpgme_data_t *DH,
        const char *BUFFER, size_t SIZE, int COPY);
typedef void (*gpgme_data_release_t)(gpgme_data_t DH);
typedef gpgme_data_type_t (*gpgme_data_identify_t)(gpgme_data_t DH);
typedef size_t (*gpgme_data_seek_t)(gpgme_data_t DH, size_t OFFSET,
        int WHENCE);
typedef size_t (*gpgme_data_read_t)(gpgme_data_t DH, void *BUFFER,
        size_t LENGTH);

// encrypt and decrypt

typedef gpgme_error_t (*gpgme_op_decrypt_t)(gpgme_ctx_t CTX,
        gpgme_data_t CIPHER, gpgme_data_t PLAIN);
typedef gpgme_error_t (*gpgme_op_verify_t)(gpgme_ctx_t CTX, gpgme_data_t SIG,
        gpgme_data_t SIGNED_TEXT, gpgme_data_t PLAIN);
typedef gpgme_error_t (*gpgme_op_decrypt_verify_t)(gpgme_ctx_t CTX,
        gpgme_data_t CIPHER, gpgme_data_t PLAIN);
typedef gpgme_decrypt_result_t (*gpgme_op_decrypt_result_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t (*gpgme_op_encrypt_sign_t)(gpgme_ctx_t CTX,
        gpgme_key_t RECP[], gpgme_encrypt_flags_t FLAGS, gpgme_data_t PLAIN,
        gpgme_data_t CIPHER);
typedef gpgme_verify_result_t (*gpgme_op_verify_result_t)(gpgme_ctx_t CTX);
typedef void (*gpgme_signers_clear_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t (*gpgme_signers_add_t)(gpgme_ctx_t CTX, const gpgme_key_t KEY);

// keys

typedef gpgme_error_t (*gpgme_get_key_t)(gpgme_ctx_t CTX, const char *FPR,
        gpgme_key_t *R_KEY, int SECRET);
typedef gpgme_error_t (*gpgme_op_genkey_t)(gpgme_ctx_t CTX, const char *PARMS,
        gpgme_data_t PUBLIC, gpgme_data_t SECRET);
typedef gpgme_genkey_result_t (*gpgme_op_genkey_result_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t (*gpgme_op_delete_t)(gpgme_ctx_t CTX,
        const gpgme_key_t KEY, int ALLOW_SECRET);
typedef gpgme_error_t (*gpgme_op_import_t)(gpgme_ctx_t CTX,
        gpgme_data_t KEYDATA);
typedef gpgme_error_t (*gpgme_op_export_t)(gpgme_ctx_t CTX,
        const char *PATTERN, gpgme_export_mode_t MODE, gpgme_data_t KEYDATA);
typedef gpgme_error_t (*gpgme_set_keylist_mode_t)(gpgme_ctx_t CTX,
        gpgme_keylist_mode_t MODE);
typedef gpgme_keylist_mode_t (*gpgme_get_keylist_mode_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t (*gpgme_op_keylist_start_t)(gpgme_ctx_t CTX,
        const char *PATTERN, int SECRET_ONLY);
typedef gpgme_error_t (*gpgme_op_keylist_next_t)(gpgme_ctx_t CTX,
        gpgme_key_t *R_KEY);
typedef gpgme_error_t (*gpgme_op_keylist_end_t)(gpgme_ctx_t CTX);
typedef gpgme_error_t (*gpgme_op_import_keys_t)(gpgme_ctx_t CTX,
        gpgme_key_t *KEYS);
typedef void (*gpgme_key_ref_t)(gpgme_key_t KEY);
typedef void (*gpgme_key_unref_t)(gpgme_key_t KEY);

typedef struct {
	const char *version;
    const char *passphrase;
	void * gpgme;
	gpgme_ctx_t ctx;

	sqlite3 *db;
	sqlite3 *system_db;

	sqlite3_stmt *log;
	sqlite3_stmt *safeword;
	sqlite3_stmt *get_identity;
	sqlite3_stmt *set_person;
	sqlite3_stmt *set_pgp_keypair;
	sqlite3_stmt *set_identity;
	sqlite3_stmt *set_trust;
    sqlite3_stmt *get_trust;

	gpgme_check_version_t gpgme_check;
	gpgme_set_locale_t gpgme_set_locale;
	gpgme_new_t gpgme_new;
	gpgme_release_t gpgme_release;
	gpgme_set_protocol_t gpgme_set_protocol;
	gpgme_set_armor_t gpgme_set_armor;

	gpgme_data_new_t gpgme_data_new;
	gpgme_data_new_from_mem_t gpgme_data_new_from_mem;
	gpgme_data_release_t gpgme_data_release;
	gpgme_data_identify_t gpgme_data_identify;
	gpgme_data_seek_t gpgme_data_seek;
	gpgme_data_read_t gpgme_data_read;

	gpgme_op_decrypt_t gpgme_op_decrypt;
	gpgme_op_verify_t gpgme_op_verify;
	gpgme_op_decrypt_verify_t gpgme_op_decrypt_verify;
	gpgme_op_decrypt_result_t gpgme_op_decrypt_result;
	gpgme_op_encrypt_sign_t gpgme_op_encrypt_sign;
	gpgme_op_verify_result_t gpgme_op_verify_result;
    gpgme_signers_clear_t gpgme_signers_clear;
    gpgme_signers_add_t gpgme_signers_add;

	gpgme_get_key_t gpgme_get_key;
	gpgme_op_genkey_t gpgme_op_genkey;
    gpgme_op_genkey_result_t gpgme_op_genkey_result;
    gpgme_op_delete_t gpgme_op_delete;
    gpgme_op_import_t gpgme_op_import;
    gpgme_op_export_t gpgme_op_export;
    gpgme_set_keylist_mode_t gpgme_set_keylist_mode;
    gpgme_get_keylist_mode_t gpgme_get_keylist_mode;
    gpgme_op_keylist_start_t gpgme_op_keylist_start;
    gpgme_op_keylist_next_t gpgme_op_keylist_next;
    gpgme_op_keylist_end_t gpgme_op_keylist_end;
    gpgme_op_import_keys_t gpgme_op_import_keys;
    gpgme_key_ref_t gpgme_key_ref;
    gpgme_key_unref_t gpgme_key_unref;
} pEpSession;

static bool ensure_keyserver()
{
    static char buf[MAX_LINELENGTH];
    int n;
    FILE *f = fopen(gpg_conf(), "r");

    if (f != NULL) {
        while (!feof(f)) {
            char * s = fgets(buf, MAX_LINELENGTH, f);
            if (s && !feof(f)) {
                char * t = strtok(s, " ");
                if (t && strcmp(t, "keyserver") == 0)
                {
                    fclose(f);
                    return true;
                }
            }
        }
        f = freopen(gpg_conf(), "a", f);
    }
    else {
        f = fopen(gpg_conf(), "w");
    }

    assert(f);
    if (f == NULL)
        return false;

    n = fprintf(f, "keyserver %s\n", DEFAULT_KEYSERVER);
    assert(n >= 0);
    fclose(f);

    return true;
}

DYNAMIC_API PEP_STATUS init(PEP_SESSION *session)
{
	gpgme_error_t gpgme_error;
	int int_result;
	const char *sql_log;
	const char *sql_safeword;
	const char *sql_get_identity;
	const char *sql_set_person;
	const char *sql_set_pgp_keypair;
	const char *sql_set_identity;
	const char *sql_set_trust;
    const char *sql_get_trust;

    bool bResult;

	assert(sqlite3_threadsafe());
	if (!sqlite3_threadsafe())
		return PEP_INIT_SQLITE3_WITHOUT_MUTEX;

	assert(session);
	*session = NULL;

    pEpSession *_session = (pEpSession *) calloc(1, sizeof(pEpSession));
	assert(_session);
	if (_session == NULL)
		return PEP_OUT_OF_MEMORY;
	
	_session->version = PEP_ENGINE_VERSION;

    bResult = ensure_keyserver();
    assert(bResult);

    // to do: implement something useful
    _session->passphrase = "";

	_session->gpgme = dlopen(LIBGPGME, RTLD_LAZY);
	if (_session->gpgme == NULL) {
		free(_session);
		return PEP_INIT_CANNOT_LOAD_GPGME;
	}

	_session->gpgme_set_locale
        = (gpgme_set_locale_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_set_locale");
	assert(_session->gpgme_set_locale);

	_session->gpgme_check
        = (gpgme_check_version_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_check_version");
	assert(_session->gpgme_check);

	_session->gpgme_new
        = (gpgme_new_t) (intptr_t) dlsym(_session->gpgme, "gpgme_new");
	assert(_session->gpgme_new);

	_session->gpgme_release
        = (gpgme_release_t) (intptr_t) dlsym(_session->gpgme, "gpgme_release");
	assert(_session->gpgme_release);

	_session->gpgme_set_protocol
        = (gpgme_set_protocol_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_set_protocol");
	assert(_session->gpgme_set_protocol);

	_session->gpgme_set_armor
        = (gpgme_set_armor_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_set_armor");
	assert(_session->gpgme_set_armor);

	_session->gpgme_data_new
        = (gpgme_data_new_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_data_new");
	assert(_session->gpgme_data_new);

	_session->gpgme_data_new_from_mem
        = (gpgme_data_new_from_mem_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_data_new_from_mem");
	assert(_session->gpgme_data_new_from_mem);

	_session->gpgme_data_release
        = (gpgme_data_release_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_data_release");
	assert(_session->gpgme_data_release);

	_session->gpgme_data_identify
        = (gpgme_data_identify_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_data_identify");
	assert(_session->gpgme_data_identify);

	_session->gpgme_data_seek
        = (gpgme_data_seek_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_data_seek");
	assert(_session->gpgme_data_seek);

	_session->gpgme_data_read
        = (gpgme_data_read_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_data_read");
	assert(_session->gpgme_data_read);

	_session->gpgme_op_decrypt
        = (gpgme_op_decrypt_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_decrypt");
	assert(_session->gpgme_op_decrypt);

	_session->gpgme_op_verify
        = (gpgme_op_verify_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_verify");
	assert(_session->gpgme_op_verify);

	_session->gpgme_op_decrypt_verify
        = (gpgme_op_decrypt_verify_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_decrypt_verify");
	assert(_session->gpgme_op_decrypt_verify);

	_session->gpgme_op_decrypt_result
        = (gpgme_op_decrypt_result_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_decrypt_result");
	assert(_session->gpgme_op_decrypt_result);

	_session->gpgme_op_encrypt_sign
        = (gpgme_op_encrypt_sign_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_encrypt_sign");
	assert(_session->gpgme_op_encrypt_sign);

	_session->gpgme_op_verify_result
        = (gpgme_op_verify_result_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_verify_result");
	assert(_session->gpgme_op_verify_result);

    _session->gpgme_signers_clear
        = (gpgme_signers_clear_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_signers_clear");
    assert(_session->gpgme_signers_clear);

    _session->gpgme_signers_add
        = (gpgme_signers_add_t) (intptr_t) dlsym(_session->gpgme,
        "gpgme_signers_add");
    assert(_session->gpgme_signers_add);

	_session->gpgme_get_key
        = (gpgme_get_key_t) (intptr_t) dlsym(_session->gpgme, "gpgme_get_key");
	assert(_session->gpgme_get_key);

	_session->gpgme_op_genkey
        = (gpgme_op_genkey_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_genkey");
	assert(_session->gpgme_op_genkey);

	_session->gpgme_op_genkey_result
        = (gpgme_op_genkey_result_t) (intptr_t) dlsym(_session->gpgme,
                "gpgme_op_genkey_result");
	assert(_session->gpgme_op_genkey_result);

    _session->gpgme_op_delete = (gpgme_op_delete_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_delete");
	assert(_session->gpgme_op_delete);

    _session->gpgme_op_import = (gpgme_op_import_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_import");
	assert(_session->gpgme_op_import);

    _session->gpgme_op_export = (gpgme_op_export_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_export");
	assert(_session->gpgme_op_export);

    _session->gpgme_set_keylist_mode = (gpgme_set_keylist_mode_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_set_keylist_mode");
	assert(_session->gpgme_set_keylist_mode);

    _session->gpgme_get_keylist_mode = (gpgme_get_keylist_mode_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_get_keylist_mode");
	assert(_session->gpgme_get_keylist_mode);

    _session->gpgme_op_keylist_start = (gpgme_op_keylist_start_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_keylist_start");
	assert(_session->gpgme_op_keylist_start);

    _session->gpgme_op_keylist_next = (gpgme_op_keylist_next_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_keylist_next");
	assert(_session->gpgme_op_keylist_next);

    _session->gpgme_op_keylist_end = (gpgme_op_keylist_end_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_keylist_end");
	assert(_session->gpgme_op_keylist_end);

    _session->gpgme_op_import_keys = (gpgme_op_import_keys_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_op_import_keys");
	assert(_session->gpgme_op_import_keys);

    _session->gpgme_key_ref = (gpgme_key_ref_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_key_ref");
	assert(_session->gpgme_key_ref);

    _session->gpgme_key_unref = (gpgme_key_unref_t) (intptr_t)
        dlsym(_session->gpgme, "gpgme_key_unref");
	assert(_session->gpgme_key_unref);

	setlocale(LC_ALL, "");
	_session->version = _session->gpgme_check(NULL);
	_session->gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

	gpgme_error = _session->gpgme_new(&_session->ctx);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		dlclose(_session->gpgme);
		free(_session);
		return PEP_INIT_GPGME_INIT_FAILED;
	}

    gpgme_error = _session->gpgme_set_protocol(_session->ctx,
            GPGME_PROTOCOL_OpenPGP);
	assert(gpgme_error == GPG_ERR_NO_ERROR);

	_session->gpgme_set_armor(_session->ctx, 1);

    assert(LOCAL_DB);
    if (LOCAL_DB == NULL) {
		_session->gpgme_release(_session->ctx);
		dlclose(_session->gpgme);
        free(_session);
        return PEP_INIT_CANNOT_OPEN_DB;
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
		sqlite3_close_v2(_session->db);
		_session->gpgme_release(_session->ctx);
		dlclose(_session->gpgme);
		free(_session);
		return PEP_INIT_CANNOT_OPEN_DB;
	}

	sqlite3_busy_timeout(_session->db, BUSY_WAIT_TIME);

    assert(SYSTEM_DB);
    if (SYSTEM_DB == NULL) {
		sqlite3_close_v2(_session->db);
		_session->gpgme_release(_session->ctx);
		dlclose(_session->gpgme);
		free(_session);
		return PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
    }

	int_result = sqlite3_open_v2(
			SYSTEM_DB, &_session->system_db,
			SQLITE_OPEN_READONLY
				| SQLITE_OPEN_FULLMUTEX
				| SQLITE_OPEN_SHAREDCACHE,
			NULL
		);

	if (int_result != SQLITE_OK) {
		sqlite3_close_v2(_session->system_db);
		sqlite3_close_v2(_session->db);
		_session->gpgme_release(_session->ctx);
		dlclose(_session->gpgme);
		free(_session);
		return PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
	}

	sqlite3_busy_timeout(_session->system_db, 1000);

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
    int_result = sqlite3_prepare_v2(_session->db, sql_log, strlen(sql_log),
            &_session->log, NULL);
	assert(int_result == SQLITE_OK);

	sql_safeword = "select id, word from wordlist where lang = lower(?1)"
                   "and id = ?2 ;";
    int_result = sqlite3_prepare_v2(_session->system_db, sql_safeword,
            strlen(sql_safeword), &_session->safeword, NULL);
	assert(int_result == SQLITE_OK);

	sql_get_identity =	"select fpr, identity.user_id, username, comm_type, lang"
                        "   from identity"
						"   join person on id = identity.user_id"
						"   join pgp_keypair on fpr = identity.main_key_id"
                        "   join trust on id = trust.user_id"
                        "       and pgp_keypair_fpr = identity.main_key_id"
						"   where address = ?1 ;";

    int_result = sqlite3_prepare_v2(_session->db, sql_get_identity,
            strlen(sql_get_identity), &_session->get_identity, NULL);
	assert(int_result == SQLITE_OK);

	sql_set_person = "insert or replace into person (id, username, lang)"
                     "values (?1, ?2, ?3) ;";
	sql_set_pgp_keypair = "insert or replace into pgp_keypair (fpr)"
                          "values (?1) ;";
    sql_set_identity = "insert or replace into identity (address, main_key_id,"
                       "user_id) values (?1, ?2, ?3) ;";
    sql_set_trust = "insert or replace into trust (user_id, pgp_keypair_fpr, comm_type)"
                        "values (?1, ?2, ?3) ;";
	
    sql_get_trust = "select user_id, comm_type from trust where user_id = ?1 and pgp_keypair_fpr = ?2 ;";

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

	sqlite3_reset(_session->log);
    sqlite3_bind_text(_session->log, 1, "init", -1, SQLITE_STATIC);
    sqlite3_bind_text(_session->log, 2, "pEp " PEP_ENGINE_VERSION, -1,
            SQLITE_STATIC);
	do {
		int_result = sqlite3_step(_session->log);
		assert(int_result == SQLITE_DONE || int_result == SQLITE_BUSY);
	} while (int_result == SQLITE_BUSY);
    sqlite3_reset(_session->log);

	*session = (void *) _session;
	return PEP_STATUS_OK;
}

DYNAMIC_API void release(PEP_SESSION session)
{
	assert(session);
	pEpSession *_session = (pEpSession *) session;

	if (_session) {
		if (_session->db) {
			sqlite3_finalize(_session->safeword);
			sqlite3_finalize(_session->log);
			sqlite3_finalize(_session->get_identity);
			sqlite3_finalize(_session->set_identity);
			sqlite3_close_v2(_session->db);
			sqlite3_close_v2(_session->system_db);
		}
		if (_session->ctx)
			_session->gpgme_release(_session->ctx);
		dlclose(_session->gpgme);
	}
	free(_session);
}

stringlist_t *new_stringlist(const char *value)
{
    stringlist_t *result = (stringlist_t *) calloc(1, sizeof(stringlist_t));
    if (result && value) {
        result->value = strdup(value);
        assert(result->value);
        if (result->value == 0) {
            free(result);
            return NULL;
        }
    }
    return result;
}

stringlist_t *stringlist_add(stringlist_t *stringlist, const char *value)
{
    assert(value);

    if (stringlist == NULL)
        return new_stringlist(value);

    if (stringlist->next != NULL)
        return stringlist_add(stringlist->next, value);

    if (stringlist->value == NULL) {
        stringlist->value = strdup(value);
        assert(stringlist->value);
        if (stringlist->value == NULL)
            return NULL;
        return stringlist;
    }

    stringlist->next = new_stringlist(value);
    assert(stringlist->next);
    if (stringlist->next == NULL)
        return NULL;

    return stringlist->next;
}

int stringlist_length(const stringlist_t *stringlist)
{
    int len = 1;
    stringlist_t *_stringlist;

    assert(stringlist);

    if (stringlist->value == NULL)
        return 0;

    for (_stringlist=stringlist->next; _stringlist!=NULL; _stringlist=_stringlist->next)
        len += 1;

    return len;
}

void free_stringlist(stringlist_t *stringlist)
{
    if (stringlist) {
        free_stringlist(stringlist->next);
        free(stringlist->value);
        free(stringlist);
    }
}

DYNAMIC_API PEP_STATUS decrypt_and_verify(
        PEP_SESSION session, const char *ctext, size_t csize,
        char **ptext, size_t *psize, stringlist_t **keylist
    )
{
	pEpSession *_session = (pEpSession *) session;

	PEP_STATUS result;
	gpgme_error_t gpgme_error;
	gpgme_data_t cipher, plain;
	gpgme_data_type_t dt;

	stringlist_t *_keylist = NULL;
	int i_key = 0;

	assert(_session);
	assert(ctext);
	assert(csize);
	assert(ptext);
	assert(psize);
	assert(keylist);

	*ptext = NULL;
	*psize = 0;
	*keylist = NULL;

    gpgme_error = _session->gpgme_data_new_from_mem(&cipher, ctext, csize, 0);
	assert(gpgme_error == GPG_ERR_NO_ERROR);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		if (gpgme_error == GPG_ERR_ENOMEM)
			return PEP_OUT_OF_MEMORY;
		else
			return PEP_UNKNOWN_ERROR;
	}

	gpgme_error = _session->gpgme_data_new(&plain);
	assert(gpgme_error == GPG_ERR_NO_ERROR);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		_session->gpgme_data_release(cipher);
		if (gpgme_error == GPG_ERR_ENOMEM)
			return PEP_OUT_OF_MEMORY;
		else
			return PEP_UNKNOWN_ERROR;
	}

	dt = _session->gpgme_data_identify(cipher);
	switch (dt) {
	case GPGME_DATA_TYPE_PGP_SIGNED:
	case GPGME_DATA_TYPE_PGP_OTHER:
        gpgme_error = _session->gpgme_op_decrypt_verify(_session->ctx, cipher,
                plain);
		assert(gpgme_error != GPG_ERR_INV_VALUE);
		assert(gpgme_error != GPG_ERR_NO_DATA);

		switch (gpgme_error) {
		case GPG_ERR_NO_ERROR:
			{
                gpgme_verify_result_t gpgme_verify_result;
                char *_buffer = NULL;
				size_t reading;
                size_t length = _session->gpgme_data_seek(plain, 0, SEEK_END);
                gpgme_signature_t gpgme_signature;

				assert(length != -1);
				_session->gpgme_data_seek(plain, 0, SEEK_SET);

				// TODO: make things less memory consuming
                // the following algorithm allocates memory for the complete
                // text

                _buffer = malloc(length + 1);
                assert(_buffer);
                if (_buffer == NULL) {
                    _session->gpgme_data_release(plain);
                    _session->gpgme_data_release(cipher);
                    return PEP_OUT_OF_MEMORY;
                }

                reading = _session->gpgme_data_read(plain, _buffer, length);
				assert(length == reading);

                gpgme_verify_result =
                    _session->gpgme_op_verify_result(_session->ctx);
				assert(gpgme_verify_result);
                gpgme_signature = gpgme_verify_result->signatures;

				if (gpgme_signature) {
                    stringlist_t *k;
                    _keylist = new_stringlist(NULL);
                    assert(_keylist);
                    if (_keylist == NULL) {
						_session->gpgme_data_release(plain);
						_session->gpgme_data_release(cipher);
                        free(_buffer);
                        return PEP_OUT_OF_MEMORY;
                    }
                    k = _keylist;

                    result = PEP_DECRYPTED_AND_VERIFIED;
					do {
                        switch (gpgme_signature->status) {
                        case GPG_ERR_NO_ERROR:
                            k = stringlist_add(k, gpgme_signature->fpr);
                            break;
                        case GPG_ERR_CERT_REVOKED:
                        case GPG_ERR_BAD_SIGNATURE:
                            result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                            break;
                        case GPG_ERR_SIG_EXPIRED:
                        case GPG_ERR_KEY_EXPIRED:
                        case GPG_ERR_NO_PUBKEY:
                            k = stringlist_add(k, gpgme_signature->fpr);
                            if (result == PEP_DECRYPTED_AND_VERIFIED)
                                result = PEP_DECRYPTED;
                            break;
                        case GPG_ERR_GENERAL:
                            break;
                        default:
                            if (result == PEP_DECRYPTED_AND_VERIFIED)
                                result = PEP_DECRYPTED;
                            break;
                        }
					} while ((gpgme_signature = gpgme_signature->next));
				} else {
					result = PEP_DECRYPTED;
				}

				if (result == PEP_DECRYPTED_AND_VERIFIED
                        || result == PEP_DECRYPTED) {
					*ptext = _buffer;
					*psize = reading;
                    (*ptext)[*psize] = 0; // safeguard for naive users
					*keylist = _keylist;
				}
                else {
                    free_stringlist(_keylist);
                    free(_buffer);
	            }
				break;
			}
		case GPG_ERR_DECRYPT_FAILED:
			result = PEP_DECRYPT_WRONG_FORMAT;
			break;
		case GPG_ERR_BAD_PASSPHRASE:
			NOT_IMPLEMENTED;
        default:
            {
                gpgme_decrypt_result_t gpgme_decrypt_result = _session->gpgme_op_decrypt_result(_session->ctx);
                result = PEP_DECRYPT_NO_KEY;

                if (gpgme_decrypt_result != NULL) {
                    if (gpgme_decrypt_result->unsupported_algorithm)
                        *keylist = new_stringlist(gpgme_decrypt_result->unsupported_algorithm);
                    else
                        *keylist = new_stringlist("");
                    assert(*keylist);
                    if (*keylist == NULL) {
                        result = PEP_OUT_OF_MEMORY;
                        break;
                    }
                    stringlist_t *_keylist = *keylist;
                    for (gpgme_recipient_t r = gpgme_decrypt_result->recipients; r != NULL; r = r->next) {
                        _keylist = stringlist_add(_keylist, r->keyid);
                        assert(_keylist);
                        if (_keylist == NULL) {
                            free_stringlist(*keylist);
                            *keylist = NULL;
                            result = PEP_OUT_OF_MEMORY;
                            break;
                        }
                    }
                    if (result == PEP_OUT_OF_MEMORY)
                        break;
                }
            }
		}
		break;

	default:
		result = PEP_DECRYPT_WRONG_FORMAT;
	}

	_session->gpgme_data_release(plain);
	_session->gpgme_data_release(cipher);
	return result;
}

DYNAMIC_API PEP_STATUS verify_text(
        PEP_SESSION session, const char *text, size_t size,
        const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
	pEpSession *_session = (pEpSession *) session;

	PEP_STATUS result;
	gpgme_error_t gpgme_error;
	gpgme_data_t d_text, d_sig;
    stringlist_t *_keylist;

    assert(session);
    assert(text);
    assert(size);
    assert(signature);
    assert(sig_size);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = _session->gpgme_data_new_from_mem(&d_text, text, size, 0);
	assert(gpgme_error == GPG_ERR_NO_ERROR);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		if (gpgme_error == GPG_ERR_ENOMEM)
			return PEP_OUT_OF_MEMORY;
		else
			return PEP_UNKNOWN_ERROR;
	}

    gpgme_error = _session->gpgme_data_new_from_mem(&d_sig, signature, sig_size, 0);
	assert(gpgme_error == GPG_ERR_NO_ERROR);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		_session->gpgme_data_release(d_text);
		if (gpgme_error == GPG_ERR_ENOMEM)
			return PEP_OUT_OF_MEMORY;
		else
			return PEP_UNKNOWN_ERROR;
	}

    gpgme_error = _session->gpgme_op_verify(_session->ctx, d_sig, d_text, NULL);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        {
            gpgme_verify_result_t gpgme_verify_result;
            gpgme_signature_t gpgme_signature;

            gpgme_verify_result =
                _session->gpgme_op_verify_result(_session->ctx);
            assert(gpgme_verify_result);
            gpgme_signature = gpgme_verify_result->signatures;

            if (gpgme_signature) {
                stringlist_t *k;
                _keylist = new_stringlist(NULL);
                assert(_keylist);
                if (_keylist == NULL) {
                    _session->gpgme_data_release(d_text);
                    _session->gpgme_data_release(d_sig);
                    return PEP_OUT_OF_MEMORY;
                }
                k = _keylist;

                result = PEP_VERIFIED;
                do {
                    k = stringlist_add(k, gpgme_signature->fpr);
                    if (k == NULL) {
                        free_stringlist(_keylist);
                        _session->gpgme_data_release(d_text);
                        _session->gpgme_data_release(d_sig);
                        return PEP_OUT_OF_MEMORY;
                    }
                    if (gpgme_signature->summary & GPGME_SIGSUM_RED) {
                        if (gpgme_signature->summary & GPGME_SIGSUM_KEY_EXPIRED
                                || gpgme_signature->summary & GPGME_SIGSUM_SIG_EXPIRED) {
                            if (result == PEP_VERIFIED
                                    || result == PEP_VERIFIED_AND_TRUSTED)
                                result = PEP_UNENCRYPTED;
                        }
                        else {
                            result = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
                            break;
                        }
                    }
                    else {
                        if (gpgme_signature->summary & GPGME_SIGSUM_VALID) {
                            if (result == PEP_VERIFIED)
                                result = PEP_VERIFIED_AND_TRUSTED;
                        }
                        if (gpgme_signature->summary & GPGME_SIGSUM_GREEN) {
                            // good
                        }
                        else if (gpgme_signature->summary & GPGME_SIGSUM_KEY_MISSING) {
                            result = PEP_VERIFY_NO_KEY;
                        }
                        else if (gpgme_signature->summary & GPGME_SIGSUM_SYS_ERROR) {
                            if (result == PEP_VERIFIED
                                    || result == PEP_VERIFIED_AND_TRUSTED)
                                result = PEP_UNENCRYPTED;
                        }
                        else {
                            // do nothing
                        }
                    }
                } while ((gpgme_signature = gpgme_signature->next));
                *keylist = _keylist;
            } else {
                result = PEP_UNENCRYPTED;
            }
            break;
        }
        break;
    case GPG_ERR_NO_DATA:
        result = PEP_DECRYPT_WRONG_FORMAT;
        break;
    case GPG_ERR_INV_VALUE:
    default:
        result = PEP_UNKNOWN_ERROR;
        break;
    }

    _session->gpgme_data_release(d_text);
    _session->gpgme_data_release(d_sig);

    return result;
}

DYNAMIC_API PEP_STATUS encrypt_and_sign(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
    )
{
	pEpSession *_session = (pEpSession *) session;

	PEP_STATUS result;
	gpgme_error_t gpgme_error;
	gpgme_data_t plain, cipher;
	gpgme_key_t *rcpt;
	gpgme_encrypt_flags_t flags;
	const stringlist_t *_keylist;
    int i, j;

	assert(_session);
	assert(keylist);
	assert(ptext);
	assert(psize);
	assert(ctext);
	assert(csize);

	*ctext = NULL;
	*csize = 0;

    gpgme_error = _session->gpgme_data_new_from_mem(&plain, ptext, psize, 0);
	assert(gpgme_error == GPG_ERR_NO_ERROR);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		if (gpgme_error == GPG_ERR_ENOMEM)
			return PEP_OUT_OF_MEMORY;
		else
			return PEP_UNKNOWN_ERROR;
	}

	gpgme_error = _session->gpgme_data_new(&cipher);
	assert(gpgme_error == GPG_ERR_NO_ERROR);
	if (gpgme_error != GPG_ERR_NO_ERROR) {
		_session->gpgme_data_release(plain);
		if (gpgme_error == GPG_ERR_ENOMEM)
			return PEP_OUT_OF_MEMORY;
		else
			return PEP_UNKNOWN_ERROR;
	}

    rcpt = (gpgme_key_t *) calloc(stringlist_length(keylist) + 1,
            sizeof(gpgme_key_t));
	assert(rcpt);
	if (rcpt == NULL) {
		_session->gpgme_data_release(plain);
		_session->gpgme_data_release(cipher);
		return PEP_OUT_OF_MEMORY;
	}

    _session->gpgme_signers_clear(_session->ctx);

    for (_keylist=keylist, i=0; _keylist!=NULL; _keylist=_keylist->next, i++) {
		assert(_keylist->value);
        gpgme_error = _session->gpgme_get_key(_session->ctx, _keylist->value,
                &rcpt[i], 0);
		assert(gpgme_error != GPG_ERR_ENOMEM);

		switch (gpgme_error) {
		case GPG_ERR_ENOMEM:
            for (j=0; j<i; j++)
                _session->gpgme_key_unref(rcpt[j]);
			free(rcpt);
			_session->gpgme_data_release(plain);
			_session->gpgme_data_release(cipher);
			return PEP_OUT_OF_MEMORY;
		case GPG_ERR_NO_ERROR:
            if (i == 0) {
                gpgme_error_t _gpgme_error = _session->gpgme_signers_add(_session->ctx, rcpt[0]);
                assert(_gpgme_error == GPG_ERR_NO_ERROR);
            }
			break;
		case GPG_ERR_EOF:
            for (j=0; j<i; j++)
                _session->gpgme_key_unref(rcpt[j]);
			free(rcpt);
			_session->gpgme_data_release(plain);
			_session->gpgme_data_release(cipher);
			return PEP_KEY_NOT_FOUND;
		case GPG_ERR_AMBIGUOUS_NAME:
            for (j=0; j<i; j++)
                _session->gpgme_key_unref(rcpt[j]);
			free(rcpt);
			_session->gpgme_data_release(plain);
			_session->gpgme_data_release(cipher);
			return PEP_KEY_HAS_AMBIG_NAME;
        default: // GPG_ERR_INV_VALUE if CTX or R_KEY is not a valid pointer or
                 // FPR is not a fingerprint or key ID
            for (j=0; j<i; j++)
                _session->gpgme_key_unref(rcpt[j]);
			free(rcpt);
			_session->gpgme_data_release(plain);
			_session->gpgme_data_release(cipher);
			return PEP_GET_KEY_FAILED;
		}
	}

	// TODO: remove that and replace with proper key management
	flags  = GPGME_ENCRYPT_ALWAYS_TRUST;

    gpgme_error = _session->gpgme_op_encrypt_sign(_session->ctx, rcpt, flags,
            plain, cipher);
	switch (gpgme_error) {
	case GPG_ERR_NO_ERROR:
		{
            char *_buffer = NULL;
			size_t reading;
            size_t length = _session->gpgme_data_seek(cipher, 0, SEEK_END);
            assert(length != -1);
			_session->gpgme_data_seek(cipher, 0, SEEK_SET);

			// TODO: make things less memory consuming
            // the following algorithm allocates a buffer for the complete text

            _buffer = (char *) malloc(length + 1);
            assert(_buffer);
            if (_buffer == NULL) {
                for (j=0; j<stringlist_length(keylist); j++)
                    _session->gpgme_key_unref(rcpt[j]);
                free(rcpt);
                _session->gpgme_data_release(plain);
                _session->gpgme_data_release(cipher);
                return PEP_OUT_OF_MEMORY;
            }

            reading = _session->gpgme_data_read(cipher, _buffer, length);
			assert(length == reading);

			*ctext = _buffer;
			*csize = reading;
			(*ctext)[*csize] = 0; // safeguard for naive users
			result = PEP_STATUS_OK;
			break;
		}
	default:
		result = PEP_UNKNOWN_ERROR;
	}

    for (j=0; j<stringlist_length(keylist); j++)
        _session->gpgme_key_unref(rcpt[j]);
	free(rcpt);
	_session->gpgme_data_release(plain);
	_session->gpgme_data_release(cipher);
	return result;
}

DYNAMIC_API PEP_STATUS log_event(
        PEP_SESSION session, const char *title, const char *entity,
        const char *description, const char *comment
    )
{
	pEpSession *_session = (pEpSession *) session;
	PEP_STATUS status = PEP_STATUS_OK;
	int result;

	assert(_session);
	assert(title);
	assert(entity);

	sqlite3_reset(_session->log);
	sqlite3_bind_text(_session->log, 1, title, -1, SQLITE_STATIC);
	sqlite3_bind_text(_session->log, 2, entity, -1, SQLITE_STATIC);
	if (description)
        sqlite3_bind_text(_session->log, 3, description, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(_session->log, 3);
	if (comment)
		sqlite3_bind_text(_session->log, 4, comment, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(_session->log, 4);
	do {
		result = sqlite3_step(_session->log);
		assert(result == SQLITE_DONE || result == SQLITE_BUSY);
		if (result != SQLITE_DONE && result != SQLITE_BUSY)
			status = PEP_UNKNOWN_ERROR;
	} while (result == SQLITE_BUSY);
	sqlite3_reset(_session->log);

	return status;
}

DYNAMIC_API PEP_STATUS safeword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        )
{
	pEpSession *_session = (pEpSession *) session;
	PEP_STATUS status = PEP_STATUS_OK;
	int result;

	assert(_session);
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

	sqlite3_reset(_session->safeword);
    sqlite3_bind_text(_session->safeword, 1, lang, -1, SQLITE_STATIC);
	sqlite3_bind_int(_session->safeword, 2, value);

	result = sqlite3_step(_session->safeword);
	if (result == SQLITE_ROW) {
        *word = strdup((const char *) sqlite3_column_text(_session->safeword,
                    1));
		if (*word)
            *wsize = sqlite3_column_bytes(_session->safeword, 1);
		else
			status = PEP_SAFEWORD_NOT_FOUND;
	} else
		status = PEP_SAFEWORD_NOT_FOUND;

	sqlite3_reset(_session->safeword);
	return status;
}

DYNAMIC_API PEP_STATUS safewords(
        PEP_SESSION session, const char *fingerprint, const char *lang,
        char **words, size_t *wsize, int max_words
    )
{
	const char *source = fingerprint;
	char *buffer = calloc(1, MAX_SAFEWORDS_SPACE);
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
	pEpSession *_session = (pEpSession *) session;
	PEP_STATUS status = PEP_STATUS_OK;
	static pEp_identity *_identity;
	int result;
	const char *_lang;

	assert(session);
	assert(address);
    assert(address[0]);

    sqlite3_reset(_session->get_identity);
    sqlite3_bind_text(_session->get_identity, 1, address, -1, SQLITE_STATIC);

    result = sqlite3_step(_session->get_identity);
	switch (result) {
	case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(_session->get_identity, 0),
                (const char *) sqlite3_column_text(_session->get_identity, 1),
                (const char *) sqlite3_column_text(_session->get_identity, 2)
                );
        assert(_identity);
        if (_identity == NULL)
            return PEP_OUT_OF_MEMORY;

        _identity->comm_type = (PEP_comm_type) sqlite3_column_int(_session->get_identity, 3);
        _lang = (const char *) sqlite3_column_text(_session->get_identity, 4);
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

    sqlite3_reset(_session->get_identity);
	return status;
}

DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    )
{
	pEpSession *_session = (pEpSession *) session;
	int result;

	assert(session);
	assert(identity);
	assert(identity->address);
	assert(identity->fpr);
	assert(identity->user_id);
	assert(identity->username);

	sqlite3_exec(_session->db, "BEGIN ;", NULL, NULL, NULL);

	sqlite3_reset(_session->set_person);
    sqlite3_bind_text(_session->set_person, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(_session->set_person, 2, identity->username, -1,
            SQLITE_STATIC);
	if (identity->lang[0])
        sqlite3_bind_text(_session->set_person, 3, identity->lang, 1,
                SQLITE_STATIC);
	else
		sqlite3_bind_null(_session->set_person, 3);
	result = sqlite3_step(_session->set_person);
	sqlite3_reset(_session->set_person);
	if (result != SQLITE_DONE) {
		sqlite3_exec(_session->db, "ROLLBACK ;", NULL, NULL, NULL);
		return PEP_CANNOT_SET_PERSON;
	}

	sqlite3_reset(_session->set_pgp_keypair);
    sqlite3_bind_text(_session->set_pgp_keypair, 1, identity->fpr, -1,
            SQLITE_STATIC);
	result = sqlite3_step(_session->set_pgp_keypair);
	sqlite3_reset(_session->set_pgp_keypair);
	if (result != SQLITE_DONE) {
		sqlite3_exec(_session->db, "ROLLBACK ;", NULL, NULL, NULL);
		return PEP_CANNOT_SET_PGP_KEYPAIR;
	}

	sqlite3_reset(_session->set_identity);
    sqlite3_bind_text(_session->set_identity, 1, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(_session->set_identity, 2, identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(_session->set_identity, 3, identity->user_id, -1,
            SQLITE_STATIC);
	result = sqlite3_step(_session->set_identity);
	sqlite3_reset(_session->set_identity);
	if (result != SQLITE_DONE) {
		sqlite3_exec(_session->db, "ROLLBACK ;", NULL, NULL, NULL);
		return PEP_CANNOT_SET_IDENTITY;
	}

	sqlite3_reset(_session->set_trust);
    sqlite3_bind_text(_session->set_trust, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(_session->set_trust, 2, identity->fpr, -1,
            SQLITE_STATIC);
	sqlite3_bind_int(_session->set_trust, 3, identity->comm_type);
	result = sqlite3_step(_session->set_trust);
	sqlite3_reset(_session->set_trust);
	if (result != SQLITE_DONE) {
		sqlite3_exec(_session->db, "ROLLBACK ;", NULL, NULL, NULL);
		return PEP_CANNOT_SET_IDENTITY;
	}

    result = sqlite3_exec(_session->db, "COMMIT ;", NULL, NULL, NULL);
	if (result == SQLITE_OK)
		return PEP_STATUS_OK;
	else
		return PEP_COMMIT_FAILED;
}

DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    )
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;
    char *parms;
    const char *template =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Name-Real: %s\n"
        "Name-Email: %s\n"
        /* "Passphrase: %s\n" */
        "Expire-Date: 1y\n"
        "</GnupgKeyParms>\n";
    int result;
    gpgme_genkey_result_t gpgme_genkey_result;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL);
    assert(identity->username);
    
    parms = calloc(1, PARMS_MAX);
    assert(parms);
    if (parms == NULL)
        return PEP_OUT_OF_MEMORY;

    result = snprintf(parms, PARMS_MAX, template, identity->username,
            identity->address); // , _session->passphrase);
    assert(result < PARMS_MAX);
    if (result >= PARMS_MAX) {
        free(parms);
        return PEP_BUFFER_TOO_SMALL;
    }

    gpgme_error = _session->gpgme_op_genkey(_session->ctx, parms, NULL, NULL);
    free(parms);

    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        return PEP_ILLEGAL_VALUE;
    case GPG_ERR_GENERAL:
        return PEP_CANNOT_CREATE_KEY;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_genkey_result = _session->gpgme_op_genkey_result(_session->ctx);
    assert(gpgme_genkey_result);
    assert(gpgme_genkey_result->fpr);

    identity->fpr = strdup(gpgme_genkey_result->fpr);

    return PEP_STATUS_OK;
}

PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr)
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);

    gpgme_error = _session->gpgme_get_key(_session->ctx, fpr, &key, 0);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        return PEP_ILLEGAL_VALUE;
    case GPG_ERR_AMBIGUOUS_NAME:
        return PEP_KEY_HAS_AMBIG_NAME;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpgme_op_delete(_session->ctx, key, 1);
    _session->gpgme_key_unref(key);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_PUBKEY:
        assert(0);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_AMBIGUOUS_NAME:
        assert(0);
        return PEP_KEY_HAS_AMBIG_NAME;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    return PEP_STATUS_OK;
}

PEP_STATUS import_key(PEP_SESSION session, const char *key_data, size_t size)
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;
    gpgme_data_t dh;

    assert(session);
    assert(key_data);

    gpgme_error = _session->gpgme_data_new_from_mem(&dh, key_data, size, 0);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpgme_op_import(_session->ctx, dh);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _session->gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    case GPG_ERR_NO_DATA:
        _session->gpgme_data_release(dh);
        return PEP_ILLEGAL_VALUE;
    default:
        assert(0);
        _session->gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    }

    _session->gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;
    gpgme_data_t dh;
    size_t _size;
    char *buffer;
    int reading;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(size);

    gpgme_error = _session->gpgme_data_new(&dh);
    assert(gpgme_error != GPG_ERR_ENOMEM);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_ENOMEM:
        return PEP_OUT_OF_MEMORY;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    }

    gpgme_error = _session->gpgme_op_export(_session->ctx, fpr,
            GPGME_EXPORT_MODE_MINIMAL, dh);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_EOF:
        _session->gpgme_data_release(dh);
        return PEP_KEY_NOT_FOUND;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _session->gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    default:
        assert(0);
        _session->gpgme_data_release(dh);
        return PEP_UNKNOWN_ERROR;
    };

    _size = _session->gpgme_data_seek(dh, 0, SEEK_END);
    assert(_size != -1);
    _session->gpgme_data_seek(dh, 0, SEEK_SET);

    buffer = malloc(_size + 1);
    assert(buffer);
    if (buffer == NULL) {
        _session->gpgme_data_release(dh);
        return PEP_OUT_OF_MEMORY;
    }

    reading = _session->gpgme_data_read(dh, buffer, _size);
    assert(_size == reading);

    // safeguard for the naive user
    buffer[_size] = 0;

    *key_data = buffer;
    *size = _size;

    _session->gpgme_data_release(dh);
    return PEP_STATUS_OK;
}

static void _switch_mode(pEpSession *_session, gpgme_keylist_mode_t remove_mode,
        gpgme_keylist_mode_t add_mode)
{
	gpgme_error_t gpgme_error;
    gpgme_keylist_mode_t mode;

    mode = _session->gpgme_get_keylist_mode(_session->ctx);

    mode &= ~remove_mode;
    mode |= add_mode;

    gpgme_error = _session->gpgme_set_keylist_mode(_session->ctx, mode);
    assert(gpgme_error == GPG_ERR_NO_ERROR);
}

PEP_STATUS recv_key(PEP_SESSION session, const char *pattern)
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(pattern);

    _switch_mode(_session, GPGME_KEYLIST_MODE_LOCAL, GPGME_KEYLIST_MODE_EXTERN);

    gpgme_error = _session->gpgme_op_keylist_start(_session->ctx, pattern, 0);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
                GPGME_KEYLIST_MODE_LOCAL);
        return PEP_UNKNOWN_ERROR;
    default:
        _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
                GPGME_KEYLIST_MODE_LOCAL);
        return PEP_GET_KEY_FAILED;
    };

    do {
        gpgme_error = _session->gpgme_op_keylist_next(_session->ctx, &key);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
        case GPG_ERR_EOF:
            break;
        case GPG_ERR_NO_ERROR:
            {
                gpgme_error_t gpgme_error;
                gpgme_key_t keys[2];

                keys[0] = key;
                keys[1] = NULL;

                gpgme_error = _session->gpgme_op_import_keys(_session->ctx, keys);
                _session->gpgme_key_unref(key);
                assert(gpgme_error != GPG_ERR_INV_VALUE);
                assert(gpgme_error != GPG_ERR_CONFLICT);
            }
            break;
        case GPG_ERR_ENOMEM:
            _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
                    GPGME_KEYLIST_MODE_LOCAL);
            _session->gpgme_op_keylist_end(_session->ctx);
            return PEP_OUT_OF_MEMORY;
        default:
            // BUG: GPGME returns an illegal value instead of GPG_ERR_EOF after
            // reading first key
#ifndef NDEBUG
            fprintf(stderr, "warning: unknown result 0x%x of"
                    " gpgme_op_keylist_next()\n", gpgme_error);
#endif
            gpgme_error = GPG_ERR_EOF;
            break;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    _session->gpgme_op_keylist_end(_session->ctx);
    _switch_mode(_session, GPGME_KEYLIST_MODE_EXTERN,
            GPGME_KEYLIST_MODE_LOCAL);
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;
    gpgme_key_t key;
    stringlist_t *_keylist;
    char *fpr;

    assert(session);
    assert(pattern);
    assert(keylist);

    *keylist = NULL;

    gpgme_error = _session->gpgme_op_keylist_start(_session->ctx, pattern, 0);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        return PEP_GET_KEY_FAILED;
    };

    _keylist = new_stringlist(NULL);
    stringlist_t *_k = _keylist;

    do {
        gpgme_error = _session->gpgme_op_keylist_next(_session->ctx, &key);
        assert(gpgme_error != GPG_ERR_INV_VALUE);
        switch (gpgme_error) {
        case GPG_ERR_EOF:
            break;
        case GPG_ERR_NO_ERROR:
            assert(key);
            assert(key->subkeys);
            fpr = key->subkeys->fpr;
            assert(fpr);
            _k = stringlist_add(_k, fpr);
            assert(_k);
            if (_k != NULL)
                break;
        case GPG_ERR_ENOMEM:
            free_stringlist(_keylist);
            _session->gpgme_op_keylist_end(_session->ctx);
            return PEP_OUT_OF_MEMORY;
        default:
            // BUG: GPGME returns an illegal value instead of GPG_ERR_EOF after
            // reading first key
#ifndef NDEBUG
            fprintf(stderr, "warning: unknown result 0x%x of"
                    " gpgme_op_keylist_next()\n", gpgme_error);
#endif
            gpgme_error = GPG_ERR_EOF;
            break;
        };
    } while (gpgme_error != GPG_ERR_EOF);

    _session->gpgme_op_keylist_end(_session->ctx);
    *keylist = _keylist;
    return PEP_STATUS_OK;
}

PEP_STATUS send_key(PEP_SESSION session, const char *pattern)
{
	pEpSession *_session = (pEpSession *) session;
	gpgme_error_t gpgme_error;

    assert(session);
    assert(pattern);

    gpgme_error = _session->gpgme_op_export(_session->ctx, pattern,
            GPGME_EXPORT_MODE_EXTERN, NULL);
    assert(gpgme_error != GPG_ERR_INV_VALUE);
    if (gpgme_error == GPG_ERR_NO_ERROR)
        return PEP_STATUS_OK;
    else
        return PEP_CANNOT_SEND_KEY;
}

void pEp_free(void *p)
{
    free(p);
}

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity)
{
    pEpSession *_session = (pEpSession *) session;
    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    assert(session);
    assert(identity);
    assert(identity->user_id);
    assert(identity->user_id[0]);
    assert(identity->fpr);
    assert(identity->fpr[0]);

    identity->comm_type = PEP_ct_unknown;

    sqlite3_reset(_session->get_trust);
    sqlite3_bind_text(_session->get_trust, 1, identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(_session->get_trust, 2, identity->fpr, -1, SQLITE_STATIC);

    result = sqlite3_step(_session->get_trust);
    switch (result) {
    case SQLITE_ROW: {
        const char * user_id = (const char *) sqlite3_column_text(_session->get_trust, 1);
        int comm_type = (PEP_comm_type) sqlite3_column_int(_session->get_trust, 2);

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

    sqlite3_reset(_session->get_trust);
    return status;
}

DYNAMIC_API PEP_STATUS get_key_rating(
    PEP_SESSION session,
    const char *fpr,
    PEP_comm_type *comm_type
    )
{
    pEpSession *_session = (pEpSession *) session;
    PEP_STATUS status = PEP_STATUS_OK;
    gpgme_error_t gpgme_error;
    gpgme_key_t key;

    assert(session);
    assert(fpr);
    assert(comm_type);
    
    *comm_type = PEP_ct_unknown;

    gpgme_error = _session->gpgme_op_keylist_start(_session->ctx, fpr, 0);
    switch (gpgme_error) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        assert(0);
        return PEP_UNKNOWN_ERROR;
    default:
        return PEP_GET_KEY_FAILED;
    };

    gpgme_error = _session->gpgme_op_keylist_next(_session->ctx, &key);
    assert(gpgme_error != GPG_ERR_INV_VALUE);

    if (key == NULL) {
        _session->gpgme_op_keylist_end(_session->ctx);
        return PEP_KEY_NOT_FOUND;
    }

    switch (key->protocol) {
    case GPGME_PROTOCOL_OpenPGP:
    case GPGME_PROTOCOL_DEFAULT:
        *comm_type = PEP_ct_OpenPGP_unconfirmed;
        break;
    case GPGME_PROTOCOL_CMS:
        *comm_type = PEP_ct_CMS_unconfirmed;
        break;
    default:
        *comm_type = PEP_ct_unknown;
        _session->gpgme_op_keylist_end(_session->ctx);
        return PEP_STATUS_OK;
    }

    switch (gpgme_error) {
    case GPG_ERR_EOF:
        break;
    case GPG_ERR_NO_ERROR:
        assert(key);
        assert(key->subkeys);
        for (gpgme_subkey_t sk = key->subkeys; sk != NULL; sk = sk->next) {
            if (sk->length < 1024)
                *comm_type = PEP_ct_key_too_short;
            else if (
                (
                       (sk->pubkey_algo == GPGME_PK_RSA)
                    || (sk->pubkey_algo == GPGME_PK_RSA_E)
                    || (sk->pubkey_algo == GPGME_PK_RSA_S)
                )
                && sk->length == 1024
            )
                *comm_type = PEP_ct_OpenPGP_1024_RSA_unconfirmed;

            if (sk->invalid) {
                *comm_type = PEP_ct_key_b0rken;
                break;
            }
            if (sk->expired) {
                *comm_type = PEP_ct_key_expired;
                break;
            }
            if (sk->revoked) {
                *comm_type = PEP_ct_key_revoked;
                break;
            }
        }
        break;
    case GPG_ERR_ENOMEM:
        _session->gpgme_op_keylist_end(_session->ctx);
        *comm_type = PEP_ct_unknown;
        return PEP_OUT_OF_MEMORY;
    default:
        // BUG: GPGME returns an illegal value instead of GPG_ERR_EOF after
        // reading first key
#ifndef NDEBUG
        fprintf(stderr, "warning: unknown result 0x%x of"
            " gpgme_op_keylist_next()\n", gpgme_error);
#endif
        gpgme_error = GPG_ERR_EOF;
        break;
    };

    _session->gpgme_op_keylist_end(_session->ctx);

    return status;
}
