// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#define _GNU_SOURCE 1

#include "platform.h"
#include "pEp_internal.h"
#include "pgp_sequoia.h"

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "wrappers.h"

// #define SEQUOIA_DB_TRACING

#define TRACING 0
#ifndef TRACING
#  ifndef NDEBUG
#    define TRACING 0
#  else
#    define TRACING 1
#  endif
#endif

// enable tracing if in debugging mode
#if TRACING
#include "status_to_string.h"

#  ifdef ANDROID
#    include <android/log.h>
#    define _T(...) do {                                                \
        __android_log_print(ANDROID_LOG_DEBUG, "pEpEngine-sequoia",     \
                            ##__VA_ARGS__);                             \
    } while (0)
#  elif _WIN32
#    define _T(...) do {                        \
		char str[256];                          \
		snprintf(str, 256, ##__VA_ARGS__);      \
		OutputDebugStringA(str);                \
    } while (0)

#  else
#    define _T(...) do {                        \
        fprintf(stderr, ##__VA_ARGS__);         \
    } while (0)
#  endif
#else
#  define _T(...) do { } while (0)
#endif

// Show the start of a tracepoint (i.e., don't print a newline).
#define TC(...) do {       \
    _T("%s: ", __func__);  \
    _T(__VA_ARGS__);       \
} while (0)

// Show a trace point.
#  define T(...) do {  \
    TC(__VA_ARGS__); \
    _T("\n");          \
} while(0)

// Verbosely displays errors.
#  define DUMP_STATUS(__de_sq_status, __de_pep_status, ...) do { \
    TC(__VA_ARGS__);                                            \
    _T(": ");                                                   \
    if (__de_sq_status) {                                       \
        _T("Sequoia: %s => ", pgp_status_to_string(__de_sq_status));   \
    }                                                           \
    _T("%s\n", pEp_status_to_string(__de_pep_status));          \
} while(0)

#  define DUMP_ERR(__de_err, __de_status, ...) do {             \
    TC(__VA_ARGS__);                                            \
    _T(": ");                                                   \
    if (__de_err) {                                             \
        _T("Sequoia: %s => ", pgp_error_to_string(__de_err));   \
        pgp_error_free(__de_err);                               \
    }                                                           \
    _T("%s\n", pEp_status_to_string(__de_status));              \
} while(0)

// If __ec_status is an error, then disable the error, set 'status' to
// it, and jump to 'out'.
#define ERROR_OUT(__e_err, __ec_status, ...) do {                   \
    PEP_STATUS ___ec_status = (__ec_status);                        \
    if ((___ec_status) != PEP_STATUS_OK) {                          \
        DUMP_ERR((__e_err), (___ec_status), ##__VA_ARGS__);         \
        status = (___ec_status);                                    \
        goto out;                                                   \
    }                                                               \
} while(0)

#ifdef SEQUOIA_DB_TRACING
int sq_sql_trace_callback (unsigned trace_constant, 
                        void* context_ptr,
                        void* P,
                        void* X) {
    switch (trace_constant) {
        case SQLITE_TRACE_STMT:
            fprintf(stderr, "SEQUOIA_SQL_DEBUG: STMT - ");
            const char* X_str = (const char*) X;
            if (!EMPTYSTR(X_str) && X_str[0] == '-' && X_str[1] == '-')
                fprintf(stderr, "%s\n", X_str);
            else
                fprintf(stderr, "%s\n", sqlite3_expanded_sql((sqlite3_stmt*)P));
            break;
        case SQLITE_TRACE_ROW:
            fprintf(stderr, "SEQUOIA_SQL_DEBUG: ROW - ");
            fprintf(stderr, "%s\n", sqlite3_expanded_sql((sqlite3_stmt*)P));
            break;            
        case SQLITE_TRACE_CLOSE:
            fprintf(stderr, "SEQUOIA_SQL_DEBUG: CLOSE - ");
            break;
        default:
            break;
    }
    return 0;
}
#endif

PEP_STATUS pgp_config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite)
{
    switch (suite) {
        // supported cipher suites
        case PEP_CIPHER_SUITE_RSA2K:
        case PEP_CIPHER_SUITE_RSA3K:
        case PEP_CIPHER_SUITE_CV25519:
        case PEP_CIPHER_SUITE_P256:
        case PEP_CIPHER_SUITE_P384:
        case PEP_CIPHER_SUITE_P521:
            session->cipher_suite = suite;
            return PEP_STATUS_OK;

        case PEP_CIPHER_SUITE_DEFAULT:
            session->cipher_suite = PEP_CIPHER_SUITE_RSA2K;
            return PEP_STATUS_OK;

        // unsupported cipher suites
        default:
            session->cipher_suite = PEP_CIPHER_SUITE_RSA2K;
            return PEP_CANNOT_CONFIG;
    }
}

static pgp_tpk_cipher_suite_t cipher_suite(PEP_CIPHER_SUITE suite)
{
    switch (suite) {
        // supported cipher suites
        case PEP_CIPHER_SUITE_RSA2K:
            return PGP_TPK_CIPHER_SUITE_RSA2K;
        case PEP_CIPHER_SUITE_RSA3K:
            return PGP_TPK_CIPHER_SUITE_RSA3K;
        case PEP_CIPHER_SUITE_CV25519:
            return PGP_TPK_CIPHER_SUITE_CV25519;
        case PEP_CIPHER_SUITE_P256:
            return PGP_TPK_CIPHER_SUITE_P256;
        case PEP_CIPHER_SUITE_P384:
            return PGP_TPK_CIPHER_SUITE_P384;
        case PEP_CIPHER_SUITE_P521:
            return PGP_TPK_CIPHER_SUITE_P521;
        default:
            return PGP_TPK_CIPHER_SUITE_RSA2K;
    }
}

int email_cmp(void *cookie, int a_len, const void *a, int b_len, const void *b)
{
    pgp_packet_t a_userid = pgp_user_id_from_raw (a, a_len);
    pgp_packet_t b_userid = pgp_user_id_from_raw (b, b_len);

    T("(%.*s, %.*s)", a_len, (const char *) a, b_len, (const char *) b);

    char *a_address = NULL;
    pgp_user_id_address_normalized(NULL, a_userid, &a_address);
    if (!a_address)
        pgp_user_id_other(NULL, a_userid, &a_address);

    char *b_address = NULL;
    pgp_user_id_address_normalized(NULL, b_userid, &b_address);
    if (!b_address)
        pgp_user_id_other(NULL, b_userid, &b_address);

    pgp_packet_free(a_userid);
    pgp_packet_free(b_userid);

    // return an integer that is negative, zero, or positive if the
    // first string is less than, equal to, or greater than the
    // second, respectively.
    int result;
    if (!a_address && !b_address)
        result = 0;
    else if (!a_address)
        result = -1;
    else if (!b_address)
        result = 1;
    else
        result = strcmp(a_address, b_address);

    if (true) {
        T("'%s' %s '%s'",
          a_address,
          result == 0 ? "==" : result < 0 ? "<" : ">",
          b_address);
    }

    free(a_address);
    free(b_address);

    return result;
}

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;

#ifdef _WIN32
	int sqlite_result;
	sqlite_result = sqlite3_open_v2(KEYS_DB,
		&session->key_db,
		SQLITE_OPEN_READWRITE
		| SQLITE_OPEN_CREATE
		| SQLITE_OPEN_FULLMUTEX
		| SQLITE_OPEN_PRIVATECACHE,
		NULL);
#else
    // Create the home directory.
    char *home_env = NULL;
#ifndef NDEBUG
    home_env = getenv("PEP_HOME");
#endif

#define PEP_KEYS_PATH "/.pEp/keys.db"

    if (!home_env)
        home_env = getenv("HOME");

    if (!home_env)
        ERROR_OUT(NULL, PEP_INIT_GPGME_INIT_FAILED, "HOME unset");

    // Create the DB and initialize it.
    size_t path_size = strlen(home_env) + sizeof(PEP_KEYS_PATH);
    char *path = (char *) calloc(1, path_size);
    assert(path);
    if (!path)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

	int r = snprintf(path, path_size, "%s" PEP_KEYS_PATH, home_env);
    assert(r >= 0 && r < path_size);
    if (r < 0)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR, "snprintf");

    int sqlite_result;
    sqlite_result = sqlite3_open_v2(path,
                                    &session->key_db,
                                    SQLITE_OPEN_READWRITE
                                    | SQLITE_OPEN_CREATE
                                    | SQLITE_OPEN_FULLMUTEX
                                    | SQLITE_OPEN_PRIVATECACHE,
                                    NULL);
    free(path);
#endif

#ifdef SEQUOIA_DB_TRACING
    sqlite3_trace_v2(session->key_db, 
        SQLITE_TRACE_STMT | SQLITE_TRACE_ROW | SQLITE_TRACE_CLOSE,
        sq_sql_trace_callback,
        NULL);    
#endif            

    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(NULL, PEP_INIT_CANNOT_OPEN_DB,
                  "opening keys DB: %s", sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_exec(session->key_db,
                                 "PRAGMA secure_delete=true;\n"
                                 "PRAGMA foreign_keys=true;\n"
                                 "PRAGMA locking_mode=NORMAL;\n"
                                 "PRAGMA journal_mode=WAL;\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(NULL, PEP_INIT_CANNOT_OPEN_DB,
                  "setting pragmas: %s", sqlite3_errmsg(session->key_db));

    sqlite3_busy_timeout(session->key_db, BUSY_WAIT_TIME);

    sqlite_result =
        sqlite3_create_collation(session->key_db,
                                "EMAIL",
                                SQLITE_UTF8,
                                /* pArg (cookie) */ NULL,
                                email_cmp);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(NULL, PEP_INIT_CANNOT_OPEN_DB,
                  "registering EMAIL collation function: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_exec(session->key_db,
                                 "CREATE TABLE IF NOT EXISTS keys (\n"
                                 "   primary_key TEXT UNIQUE PRIMARY KEY,\n"
                                 "   secret BOOLEAN,\n"
                                 "   tpk BLOB\n"
                                 ");\n"
                                 "CREATE INDEX IF NOT EXISTS keys_index\n"
                                 "  ON keys (primary_key, secret)\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(NULL, PEP_INIT_CANNOT_OPEN_DB,
                  "creating keys table: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_exec(session->key_db,
                                 "CREATE TABLE IF NOT EXISTS subkeys (\n"
                                 "   subkey TEXT NOT NULL,\n"
                                 "   primary_key TEXT NOT NULL,\n"
                                 "   UNIQUE(subkey, primary_key),\n"
                                 "   FOREIGN KEY (primary_key)\n"
                                 "       REFERENCES keys(primary_key)\n"
                                 "     ON DELETE CASCADE\n"
                                 ");\n"
                                 "CREATE INDEX IF NOT EXISTS subkeys_index\n"
                                 "  ON subkeys (subkey, primary_key)\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(NULL, PEP_INIT_CANNOT_OPEN_DB,
                  "creating subkeys table: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_exec(session->key_db,
                                 "CREATE TABLE IF NOT EXISTS userids (\n"
                                 "   userid TEXT NOT NULL COLLATE EMAIL,\n"
                                 "   primary_key TEXT NOT NULL,\n"
                                 "   UNIQUE(userid, primary_key),\n"
                                 "   FOREIGN KEY (primary_key)\n"
                                 "       REFERENCES keys(primary_key)\n"
                                 "     ON DELETE CASCADE\n"
                                 ");\n"
                                 "CREATE INDEX IF NOT EXISTS userids_index\n"
                                 "  ON userids (userid COLLATE EMAIL, primary_key)\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(NULL, PEP_INIT_CANNOT_OPEN_DB,
                  "creating userids table: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "begin transaction",
                             -1, &session->sq_sql.begin_transaction, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "commit transaction",
                             -1, &session->sq_sql.commit_transaction, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "rollback transaction",
                             -1, &session->sq_sql.rollback_transaction, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM keys"
                             " WHERE primary_key == ?",
                             -1, &session->sq_sql.tpk_find, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM keys"
                             " WHERE primary_key == ? and secret == 1",
                             -1, &session->sq_sql.tsk_find, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM subkeys"
                             " LEFT JOIN keys"
                             "  ON subkeys.primary_key == keys.primary_key"
                             " WHERE subkey == ?",
                             -1, &session->sq_sql.tpk_find_by_keyid, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM subkeys"
                             " LEFT JOIN keys"
                             "  ON subkeys.primary_key == keys.primary_key"
                             " WHERE subkey == ?",
                             -1, &session->sq_sql.tpk_find_by_keyid, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM subkeys"
                             " LEFT JOIN keys"
                             "  ON subkeys.primary_key == keys.primary_key"
                             " WHERE subkey == ? and keys.secret == 1",
                             -1, &session->sq_sql.tsk_find_by_keyid, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM userids"
                             " LEFT JOIN keys"
                             "  ON userids.primary_key == keys.primary_key"
                             " WHERE userid == ?",
                             -1, &session->sq_sql.tpk_find_by_email, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT tpk, secret FROM userids"
                             " LEFT JOIN keys"
                             "  ON userids.primary_key == keys.primary_key"
                             " WHERE userid == ? and keys.secret == 1",
                             -1, &session->sq_sql.tsk_find_by_email, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "select tpk, secret from keys",
                             -1, &session->sq_sql.tpk_all, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "select tpk, secret from keys where secret = 1",
                             -1, &session->sq_sql.tsk_all, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "INSERT OR REPLACE INTO keys"
                             "   (primary_key, secret, tpk)"
                             " VALUES (?, ?, ?)",
                             -1, &session->sq_sql.tpk_save_insert_primary, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "INSERT OR REPLACE INTO subkeys"
                             "   (subkey, primary_key)"
                             " VALUES (?, ?)",
                             -1, &session->sq_sql.tpk_save_insert_subkeys, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "INSERT OR REPLACE INTO userids"
                             "   (userid, primary_key)"
                             " VALUES (?, ?)",
                             -1, &session->sq_sql.tpk_save_insert_userids, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "DELETE FROM keys WHERE primary_key = ?",
                             -1, &session->sq_sql.delete_keypair, NULL);
    assert(sqlite_result == SQLITE_OK);

 out:
    if (status != PEP_STATUS_OK)
        pgp_release(session, in_first);
    return status;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    sqlite3_stmt **stmts = (sqlite3_stmt **) &session->sq_sql;
    for (int i = 0; i < sizeof(session->sq_sql) / sizeof(*stmts); i ++)
        if (stmts[i]) {
            sqlite3_finalize(stmts[i]);
            stmts[i] = NULL;
        }

    if (session->key_db) {
        int result = sqlite3_close_v2(session->key_db);
        if (result != 0)
            DUMP_ERR(NULL, PEP_UNKNOWN_ERROR,
                     "Closing key DB: sqlite3_close_v2: %s",
                     sqlite3_errstr(result));
        session->key_db = NULL;
    }
}

// Ensures that a fingerprint is in canonical form.  A canonical
// fingerprint doesn't contain any white space.
//
// This function does *not* consume fpr.
static char *pgp_fingerprint_canonicalize(const char *) __attribute__((nonnull));
static char *pgp_fingerprint_canonicalize(const char *fpr)
{
    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    char *fpr_canonicalized = pgp_fingerprint_to_hex(pgp_fpr);
    pgp_fingerprint_free(pgp_fpr);

    return fpr_canonicalized;
}

// step statement and load the tpk and secret.
static PEP_STATUS key_load(PEP_SESSION, sqlite3_stmt *, pgp_tpk_t *, int *)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS key_load(PEP_SESSION session, sqlite3_stmt *stmt,
                           pgp_tpk_t *tpkp, int *secretp)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_result = Sqlite3_step(stmt);
    switch (sqlite_result) {
    case SQLITE_ROW:
        if (tpkp) {
            int data_len = sqlite3_column_bytes(stmt, 0);
            const void *data = sqlite3_column_blob(stmt, 0);

            pgp_error_t err = NULL;
            *tpkp = pgp_tpk_from_bytes(&err, data, data_len);
            if (!*tpkp)
                ERROR_OUT(err, PEP_GET_KEY_FAILED, "parsing TPK");
        }

        if (secretp)
            *secretp = sqlite3_column_int(stmt, 1);

        break;
    case SQLITE_DONE:
        // Got nothing.
        status = PEP_KEY_NOT_FOUND;
        break;
    default:
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                  "stepping: %s", sqlite3_errmsg(session->key_db));
    }

 out:
    T(" -> %s", pEp_status_to_string(status));
    return status;
}

// step statement until exhausted and load the tpks.
static PEP_STATUS key_loadn(PEP_SESSION, sqlite3_stmt *, pgp_tpk_t **, int *)
    __attribute__((nonnull));
static PEP_STATUS key_loadn(PEP_SESSION session, sqlite3_stmt *stmt,
                            pgp_tpk_t **tpksp, int *tpks_countp)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int tpks_count = 0;
    int tpks_capacity = 8;
    pgp_tpk_t *tpks = calloc(tpks_capacity, sizeof(pgp_tpk_t));
    if (!tpks)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    for (;;) {
        pgp_tpk_t tpk = NULL;
        status = key_load(session, stmt, &tpk, NULL);
        if (status == PEP_KEY_NOT_FOUND) {
            status = PEP_STATUS_OK;
            break;
        }
        ERROR_OUT(NULL, status, "loading TPK");

        if (tpks_count == tpks_capacity) {
            tpks_capacity *= 2;
            tpks = realloc(tpks, sizeof(tpks[0]) * tpks_capacity);
            if (!tpks)
                ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "tpks");
        }
        tpks[tpks_count ++] = tpk;
    }

 out:
    if (status != PEP_STATUS_OK) {
        for (int i = 0; i < tpks_count; i ++)
            pgp_tpk_free(tpks[i]);
        free(tpks);
    } else {
        *tpksp = tpks;
        *tpks_countp = tpks_count;
    }

    T(" -> %s (%d tpks)", pEp_status_to_string(status), *tpks_countp);
    return status;
}

// Returns the TPK identified by the provided fingerprint.
//
// This function only matches on the primary key!
static PEP_STATUS tpk_find(PEP_SESSION, pgp_fingerprint_t, int, pgp_tpk_t *, int *)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS tpk_find(PEP_SESSION session,
                           pgp_fingerprint_t fpr, int private_only,
                           pgp_tpk_t *tpk, int *secret)
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *fpr_str = pgp_fingerprint_to_hex(fpr);

    T("(%s, %d)", fpr_str, private_only);

    sqlite3_stmt *stmt
        = private_only ? session->sq_sql.tsk_find : session->sq_sql.tpk_find;
    sqlite3_bind_text(stmt, 1, fpr_str, -1, SQLITE_STATIC);

    status = key_load(session, stmt, tpk, secret);
    ERROR_OUT(NULL, status, "Looking up %s", fpr_str);

 out:
    sqlite3_reset(stmt);
    T("(%s, %d) -> %s", fpr_str, private_only, pEp_status_to_string(status));
    free(fpr_str);
    return status;
}

// Returns the TPK identified by the provided keyid.
//
// This function matches on both primary keys and subkeys!
//
// Note: There can be multiple TPKs for a given keyid.  This can
// occur, because an encryption subkey can be bound to multiple TPKs.
// Also, it is possible to collide key ids.  If there are multiple key
// ids for a given key, this just returns one of them.
//
// If private_only is set, this will only consider TPKs with some
// secret key material.
static PEP_STATUS tpk_find_by_keyid_hex(PEP_SESSION, const char *, int, pgp_tpk_t *, int *)
  __attribute__((nonnull(1, 2)));
static PEP_STATUS tpk_find_by_keyid_hex(
        PEP_SESSION session, const char *keyid_hex, int private_only,
        pgp_tpk_t *tpkp, int *secretp)
{
    PEP_STATUS status = PEP_STATUS_OK;
    T("(%s, %d)", keyid_hex, private_only);

    sqlite3_stmt *stmt
        = private_only ? session->sq_sql.tsk_find_by_keyid : session->sq_sql.tpk_find_by_keyid;
    sqlite3_bind_text(stmt, 1, keyid_hex, -1, SQLITE_STATIC);

    status = key_load(session, stmt, tpkp, secretp);
    ERROR_OUT(NULL, status, "Looking up %s", keyid_hex);

 out:
    sqlite3_reset(stmt);
    T("(%s, %d) -> %s", keyid_hex, private_only, pEp_status_to_string(status));
    return status;
}

// See tpk_find_by_keyid_hex.
PEP_STATUS tpk_find_by_keyid(PEP_SESSION, pgp_keyid_t, int, pgp_tpk_t *, int *)
    __attribute__((nonnull(1, 2)));
PEP_STATUS tpk_find_by_keyid(PEP_SESSION session,
                             pgp_keyid_t keyid, int private_only,
                             pgp_tpk_t *tpkp, int *secretp)
{
    char *keyid_hex = pgp_keyid_to_hex(keyid);
    if (! keyid_hex)
        return PEP_OUT_OF_MEMORY;
    PEP_STATUS status
        = tpk_find_by_keyid_hex(session, keyid_hex, private_only, tpkp, secretp);
    free(keyid_hex);
    return status;
}

// See tpk_find_by_keyid_hex.
static PEP_STATUS tpk_find_by_fpr(PEP_SESSION, pgp_fingerprint_t, int,
                                  pgp_tpk_t *, int *)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS tpk_find_by_fpr(
    PEP_SESSION session, pgp_fingerprint_t fpr, int private_only,
    pgp_tpk_t *tpkp, int *secretp)
{
    pgp_keyid_t keyid = pgp_fingerprint_to_keyid(fpr);
    if (! keyid)
        return PEP_OUT_OF_MEMORY;
    PEP_STATUS status
        = tpk_find_by_keyid(session, keyid, private_only, tpkp, secretp);
    pgp_keyid_free(keyid);
    return status;
}

// See tpk_find_by_keyid_hex.
static PEP_STATUS tpk_find_by_fpr_hex(PEP_SESSION, const char *, int, pgp_tpk_t *, int *secret)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS tpk_find_by_fpr_hex(
    PEP_SESSION session, const char *fpr, int private_only,
    pgp_tpk_t *tpkp, int *secretp)
{
    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    if (! pgp_fpr)
        return PEP_OUT_OF_MEMORY;
    PEP_STATUS status
        = tpk_find_by_fpr(session, pgp_fpr, private_only, tpkp, secretp);
    pgp_fingerprint_free(pgp_fpr);
    return status;
}

// Returns all known TPKs.
static PEP_STATUS tpk_all(PEP_SESSION, int, pgp_tpk_t **, int *) __attribute__((nonnull));
static PEP_STATUS tpk_all(PEP_SESSION session, int private_only,
                          pgp_tpk_t **tpksp, int *tpks_countp) {
    PEP_STATUS status = PEP_STATUS_OK;
    sqlite3_stmt *stmt = private_only ? session->sq_sql.tsk_all : session->sq_sql.tpk_all;
    status = key_loadn(session, stmt, tpksp, tpks_countp);
    ERROR_OUT(NULL, status, "loading TPKs");
 out:
    sqlite3_reset(stmt);
    return status;
}

// Returns keys that have a user id that matches the specified pattern.
//
// The keys returned must be freed using pgp_tpk_free.
static PEP_STATUS tpk_find_by_email(PEP_SESSION, const char *, int, pgp_tpk_t **, int *)
    __attribute__((nonnull));
static PEP_STATUS tpk_find_by_email(PEP_SESSION session,
                                    const char *pattern, int private_only,
                                    pgp_tpk_t **tpksp, int *countp)
{
    PEP_STATUS status = PEP_STATUS_OK;
    T("(%s)", pattern);

    sqlite3_stmt *stmt
        = private_only ? session->sq_sql.tsk_find_by_email : session->sq_sql.tpk_find_by_email;
    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);

    status = key_loadn(session, stmt, tpksp, countp);
    ERROR_OUT(NULL, status, "Searching for '%s'", pattern);

 out:
    sqlite3_reset(stmt);
    T("(%s) -> %s (%d results)", pattern, pEp_status_to_string(status), *countp);
    return status;
}


// Saves the specified TPK.
//
// This function takes ownership of TPK.
static PEP_STATUS tpk_save(PEP_SESSION, pgp_tpk_t, identity_list **)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS tpk_save(PEP_SESSION session, pgp_tpk_t tpk,
                           identity_list **private_idents)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_fingerprint_t pgp_fpr = NULL;
    char *fpr = NULL;
    void *tsk_buffer = NULL;
    size_t tsk_buffer_len = 0;
    int tried_commit = 0;
    pgp_tpk_key_iter_t key_iter = NULL;
    pgp_user_id_binding_iter_t user_id_iter = NULL;
    char *email = NULL;
    char *name = NULL;

    sqlite3_stmt *stmt = session->sq_sql.begin_transaction;
    int sqlite_result = Sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (sqlite_result != SQLITE_DONE)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                  "begin transaction failed: %s",
                  sqlite3_errmsg(session->key_db));

    pgp_fpr = pgp_tpk_fingerprint(tpk);
    fpr = pgp_fingerprint_to_hex(pgp_fpr);
    T("(%s, private_idents: %s)", fpr, private_idents ? "yes" : "no");

    // Merge any existing data into TPK.
    pgp_tpk_t current = NULL;
    status = tpk_find(session, pgp_fpr, false, &current, NULL);
    if (status == PEP_KEY_NOT_FOUND)
        status = PEP_STATUS_OK;
    else
        ERROR_OUT(NULL, status, "Looking up %s", fpr);
    if (current) {
        tpk = pgp_tpk_merge(&err, tpk, current);
        if (! tpk)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Merging TPKs");
    }

    int is_tsk = pgp_tpk_is_tsk(tpk);

    // Serialize it.
    pgp_writer_t writer = pgp_writer_alloc(&tsk_buffer, &tsk_buffer_len);
    if (! writer)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    pgp_status_t pgp_status;
    pgp_tsk_t tsk = pgp_tpk_as_tsk(tpk);
    pgp_status = pgp_tsk_serialize(&err, tsk, writer);
    pgp_tsk_free(tsk);
    //pgp_writer_free(writer);
    if (pgp_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Serializing TPK");


    // Insert the TSK into the DB.
    stmt = session->sq_sql.tpk_save_insert_primary;
    sqlite3_bind_text(stmt, 1, fpr, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, is_tsk);
    sqlite3_bind_blob(stmt, 3, tsk_buffer, tsk_buffer_len, SQLITE_STATIC);

    sqlite_result = Sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (sqlite_result != SQLITE_DONE)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                  "Saving TPK: %s", sqlite3_errmsg(session->key_db));

    // Insert the "subkeys" (the primary key and the subkeys).
    stmt = session->sq_sql.tpk_save_insert_subkeys;
    // This inserts all of the keys in the TPK, i.e., revoked and
    // expired keys, which is what we want.
    key_iter = pgp_tpk_key_iter_all(tpk);
    pgp_key_t key;
    while ((key = pgp_tpk_key_iter_next(key_iter, NULL, NULL))) {
        pgp_keyid_t keyid = pgp_key_keyid(key);
        char *keyid_hex = pgp_keyid_to_hex(keyid);
        sqlite3_bind_text(stmt, 1, keyid_hex, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, fpr, -1, SQLITE_STATIC);

        sqlite_result = Sqlite3_step(stmt);
        sqlite3_reset(stmt);
        free(keyid_hex);
        pgp_keyid_free(keyid);
        if (sqlite_result != SQLITE_DONE) {
            pgp_tpk_key_iter_free(key_iter);
            ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                      "Updating subkeys: %s", sqlite3_errmsg(session->key_db));
        }
    }
    pgp_tpk_key_iter_free(key_iter);
    key_iter = NULL;

    // Insert the "userids".
    stmt = session->sq_sql.tpk_save_insert_userids;
    user_id_iter = pgp_tpk_user_id_binding_iter(tpk);
    pgp_user_id_binding_t binding;
    int first = 1;
    while ((binding = pgp_user_id_binding_iter_next(user_id_iter))) {
        char *user_id_value = pgp_user_id_binding_user_id(binding);
        if (!user_id_value || !*user_id_value)
            continue;

        // Ignore bindings with a self-revocation certificate, but no
        // self-signature.
        if (!pgp_user_id_binding_selfsig(binding)) {
            free(user_id_value);
            continue;
        }

        free(name);
        name = NULL;
        free(email);
        email = NULL;

        pgp_packet_t userid = pgp_user_id_new (user_id_value);
        pgp_user_id_name(NULL, userid, &name);
        pgp_user_id_address_or_other(NULL, userid, &email);
        pgp_packet_free(userid);
        free(user_id_value);

        if (email) {
            T("  userid: %s", email);

            sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, fpr, -1, SQLITE_STATIC);

            sqlite_result = Sqlite3_step(stmt);
            sqlite3_reset(stmt);

            if (sqlite_result != SQLITE_DONE) {
                pgp_user_id_binding_iter_free(user_id_iter);
                ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                          "Updating userids: %s", sqlite3_errmsg(session->key_db));
            }
        }

        if (first && private_idents && is_tsk) {
            first = 0;

            // Create an identity for the primary user id.
            pEp_identity *ident = new_identity(email, fpr, NULL, name);
            if (ident == NULL)
                ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "new_identity");

            *private_idents = identity_list_add(*private_idents, ident);
            if (*private_idents == NULL)
                ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "identity_list_add");
        }

    }
    pgp_user_id_binding_iter_free(user_id_iter);
    user_id_iter = NULL;

 out:
    // Prevent ERROR_OUT from causing an infinite loop.
    if (! tried_commit) {
        tried_commit = 1;
        stmt = status == PEP_STATUS_OK
            ? session->sq_sql.commit_transaction
            : session->sq_sql.rollback_transaction;
        int sqlite_result = Sqlite3_step(stmt);
        sqlite3_reset(stmt);
        if (sqlite_result != SQLITE_DONE)
            ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                      status == PEP_STATUS_OK
                      ? "commit failed: %s" : "rollback failed: %s",
                      sqlite3_errmsg(session->key_db));
    }

    T("(%s) -> %s", fpr, pEp_status_to_string(status));

    free(email);
    free(name);
    pgp_user_id_binding_iter_free(user_id_iter);
    pgp_tpk_key_iter_free(key_iter);
    if (stmt)
      sqlite3_reset(stmt);
    free(tsk_buffer);
    pgp_tpk_free(tpk);
    free(fpr);
    pgp_fingerprint_free(pgp_fpr);

    return status;
}

struct decrypt_cookie {
    PEP_SESSION session;
    int get_secret_keys_called;
    stringlist_t *recipient_keylist;
    stringlist_t *signer_keylist;
    int good_checksums;
    int good_but_expired;
    int good_but_revoked;
    int missing_keys;
    int bad_checksums;

    // Whether we decrypted anything.
    int decrypted;

    // The filename stored in the literal data packet.  Note: this is
    // *not* protected by the signature and should not be trusted!!!
    char *filename;
};

static pgp_status_t
get_public_keys_cb(void *cookie_raw,
                   pgp_keyid_t *keyids, size_t keyids_len,
                   pgp_tpk_t **tpks, size_t *tpk_len,
                   void (**our_free)(void *))
{
    struct decrypt_cookie *cookie = cookie_raw;
    PEP_SESSION session = cookie->session;

    *tpks = calloc(keyids_len, sizeof(*tpks));
    if (!*tpks)
        return PGP_STATUS_UNKNOWN_ERROR;
    *our_free = free;

    int i, j;
    j = 0;
    for (i = 0; i < keyids_len; i ++) {
        pgp_tpk_t tpk = NULL;
        PEP_STATUS status
            = tpk_find_by_keyid(session, keyids[i], false, &tpk, NULL);
        if (status == PEP_STATUS_OK)
            (*tpks)[j ++] = tpk;
    }
    *tpk_len = j;
    return PGP_STATUS_SUCCESS;
}

static pgp_status_t
decrypt_cb(void *cookie_opaque,
           pgp_pkesk_t *pkesks, size_t pkesk_count,
           pgp_skesk_t *skesks, size_t skesk_count,
           pgp_decryptor_do_decrypt_cb_t *decrypt,
           void *decrypt_cookie,
           pgp_fingerprint_t *identity_out)
{
    pgp_error_t err = NULL;
    struct decrypt_cookie *cookie = cookie_opaque;
    PEP_SESSION session = cookie->session;
    pgp_tpk_t *tsks = NULL;
    int tsks_count = 0;
    int wildcards = 0;

    if (cookie->get_secret_keys_called)
        // Prevent iterations, which isn't needed since we don't
        // support SKESKs.
        return PGP_STATUS_UNKNOWN_ERROR;
    cookie->get_secret_keys_called = 1;

    T("%zd PKESKs", pkesk_count);

    for (int i = 0; i < pkesk_count; i ++) {
        pgp_pkesk_t pkesk = pkesks[i];
        pgp_keyid_t keyid = pgp_pkesk_recipient(pkesk); /* Reference. */
        char *keyid_str = pgp_keyid_to_hex(keyid);
        pgp_tpk_key_iter_t key_iter = NULL;
        pgp_session_key_t sk = NULL;

        T("Considering PKESK for %s", keyid_str);

        if (strcmp(keyid_str, "0000000000000000") == 0) {
            // Initially ignore wildcards.
            wildcards = 1;
            goto eol;
        }

        // Collect the recipients.  Note: we must return the primary
        // key's fingerprint.
        pgp_tpk_t tpk = NULL;
        int is_tsk = 0;
        if (tpk_find_by_keyid(session, keyid, false, &tpk, &is_tsk) != PEP_STATUS_OK)
            goto eol;

        pgp_fingerprint_t fp = pgp_tpk_fingerprint(tpk);
        char *fp_string = pgp_fingerprint_to_hex(fp);
        stringlist_add_unique(cookie->recipient_keylist, fp_string);
        free(fp_string);
        pgp_fingerprint_free(fp);

        if (cookie->decrypted)
            goto eol;

        // See if we have the secret key.
        assert(is_tsk == pgp_tpk_is_tsk(tpk));
        if (! is_tsk)
            goto eol;

        key_iter = pgp_tpk_key_iter_all(tpk);
        pgp_key_t key;
        while ((key = pgp_tpk_key_iter_next(key_iter, NULL, NULL))) {
            pgp_keyid_t this_keyid = pgp_key_keyid(key);
            char *this_keyid_hex = pgp_keyid_to_hex(this_keyid);
            pgp_keyid_free(this_keyid);

            int match = strcmp(keyid_str, this_keyid_hex) == 0;
            free(this_keyid_hex);
            if (match)
                break;
        }

        if (key == NULL) {
            assert(!"Inconsistent DB: key doesn't contain a subkey with keyid!");
            goto eol;
        }

        uint8_t algo;
        uint8_t session_key[1024];
        size_t session_key_len = sizeof(session_key);
        if (pgp_pkesk_decrypt(&err, pkesk, key, &algo,
                              session_key, &session_key_len) != 0) {
            DUMP_ERR(err, PEP_UNKNOWN_ERROR, "pgp_pkesk_decrypt");
            goto eol;
        }

        sk = pgp_session_key_from_bytes (session_key, session_key_len);
        pgp_status_t status;
        if ((status = decrypt (decrypt_cookie, algo, sk))) {
            DUMP_STATUS(status, PEP_UNKNOWN_ERROR, "decrypt_cb");
            goto eol;
        }

        T("Decrypted PKESK for %s", keyid_str);

        *identity_out = pgp_tpk_fingerprint(tpk);
        cookie->decrypted = 1;

    eol:
        pgp_session_key_free (sk);
        free(keyid_str);
        pgp_tpk_key_iter_free(key_iter);
        pgp_tpk_free(tpk);
    }

    // Consider wildcard recipients.
    if (wildcards) for (int i = 0; i < pkesk_count && !cookie->decrypted; i ++) {
        pgp_pkesk_t pkesk = pkesks[i];
        pgp_keyid_t keyid = pgp_pkesk_recipient(pkesk); /* Reference. */
        char *keyid_str = pgp_keyid_to_hex(keyid);
        pgp_tpk_key_iter_t key_iter = NULL;
        pgp_session_key_t sk = NULL;

        if (strcmp(keyid_str, "0000000000000000") != 0)
            goto eol2;

        if (!tsks) {
            if (tpk_all(session, true, &tsks, &tsks_count) != PEP_STATUS_OK) {
                DUMP_ERR(NULL, PEP_UNKNOWN_ERROR, "Getting all tsks");
            }
        }

        for (int j = 0; j < tsks_count; j ++) {
            pgp_tpk_t tsk = tsks[j];

            key_iter = pgp_tpk_key_iter_all(tsk);
            pgp_key_t key;
            pgp_signature_t selfsig;
            while ((key = pgp_tpk_key_iter_next(key_iter, &selfsig, NULL))) {
                if (! (pgp_signature_can_encrypt_at_rest(selfsig)
                       || pgp_signature_can_encrypt_for_transport(selfsig)))
                    continue;

                fprintf(stderr, "key: %s\n", pgp_key_debug(key));

                // Note: for decryption to appear to succeed, we must
                // get a valid algorithm (8 of 256 values) and a
                // 16-bit checksum must match.  Thus, we have about a
                // 1 in 2**21 chance of having a false positive here.
                uint8_t algo;
                uint8_t session_key[1024];
                size_t session_key_len = sizeof(session_key);
                if (pgp_pkesk_decrypt(&err, pkesk, key,
                                      &algo, session_key, &session_key_len)) {
                    pgp_error_free(err);
                    err = NULL;
                    continue;
                }

                // Add it to the recipient list.
                pgp_fingerprint_t fp = pgp_tpk_fingerprint(tsk);
                char *fp_string = pgp_fingerprint_to_hex(fp);
                T("wildcard recipient appears to be %s", fp_string);
                stringlist_add_unique(cookie->recipient_keylist, fp_string);
                free(fp_string);
                pgp_fingerprint_free(fp);

                pgp_session_key_t sk = pgp_session_key_from_bytes (session_key,
                                                                   session_key_len);
                pgp_status_t status;
                if ((status = decrypt (decrypt_cookie, algo, sk))) {
                    DUMP_STATUS(status, PEP_UNKNOWN_ERROR, "decrypt_cb");
                    goto eol2;
                }

                *identity_out = pgp_tpk_fingerprint(tsk);
                cookie->decrypted = 1;

                break;
            }

            pgp_tpk_key_iter_free(key_iter);
            key_iter = NULL;
        }
    eol2:
        pgp_session_key_free (sk);
        free(keyid_str);
        pgp_tpk_key_iter_free(key_iter);
    }

    if (tsks) {
        for (int i = 0; i < tsks_count; i ++)
            pgp_tpk_free(tsks[i]);
        free(tsks);
    }

    return cookie->decrypted ? PGP_STATUS_SUCCESS : PGP_STATUS_UNKNOWN_ERROR;
}

static pgp_status_t
check_signatures_cb(void *cookie_opaque, pgp_message_structure_t structure)
{
    struct decrypt_cookie *cookie = cookie_opaque;
    PEP_SESSION session = cookie->session;

    pgp_message_structure_iter_t iter
        = pgp_message_structure_iter (structure);
    for (pgp_message_layer_t layer = pgp_message_structure_iter_next (iter);
         layer;
         layer = pgp_message_structure_iter_next (iter)) {
        pgp_verification_result_iter_t results;

        switch (pgp_message_layer_variant (layer)) {
        case PGP_MESSAGE_LAYER_COMPRESSION:
        case PGP_MESSAGE_LAYER_ENCRYPTION:
            break;

        case PGP_MESSAGE_LAYER_SIGNATURE_GROUP:
            pgp_message_layer_signature_group(layer, &results);
            pgp_verification_result_t result;
            while ((result = pgp_verification_result_iter_next (results))) {
                pgp_signature_t sig;
                pgp_keyid_t keyid = NULL;
                char *keyid_str = NULL;

                switch (pgp_verification_result_variant (result)) {
                case PGP_VERIFICATION_RESULT_GOOD_CHECKSUM:
                    // We need to add the fingerprint of the primary
                    // key to cookie->signer_keylist.

                    pgp_verification_result_good_checksum (result, &sig, NULL,
                                                           NULL, NULL, NULL);

                    // First try looking up by the TPK using the
                    // IssuerFingerprint subpacket.
                    pgp_fingerprint_t fpr
                        = pgp_signature_issuer_fingerprint(sig);
                    if (fpr) {
                        // Even though we have a fingerprint, we have
                        // to look the key up by keyid, because we
                        // want to match on subkeys and we only store
                        // keyids for subkeys.
                        keyid = pgp_fingerprint_to_keyid(fpr);
                        pgp_fingerprint_free(fpr);
                    } else {
                        // That is not available, try using the Issuer
                        // subpacket.
                        keyid = pgp_signature_issuer(sig);
                    }

                    if (! keyid) {
                        T("signature with no Issuer or Issuer Fingerprint subpacket!");
                        goto eol;
                    }

                    pgp_tpk_t tpk;
                    if (tpk_find_by_keyid(session, keyid, false,
                                          &tpk, NULL) != PEP_STATUS_OK)
                        ; // Soft error.  Ignore.

                    keyid_str = pgp_keyid_to_string (keyid);

                    if (tpk) {
                        // Ok, we have a TPK.

                        // We need the primary key's fingerprint (not
                        // the issuer fingerprint).
                        pgp_fingerprint_t primary_fpr
                            = pgp_tpk_fingerprint(tpk);
                        char *primary_fpr_str
                            = pgp_fingerprint_to_hex(primary_fpr);

                        bool good = true;

                        // Make sure the TPK is not revoked, it's
                        // creation time is <= now, and it hasn't
                        // expired.
                        pgp_revocation_status_t rs = pgp_tpk_revocation_status(tpk);
                        bool revoked = (pgp_revocation_status_variant(rs)
                                        == PGP_REVOCATION_STATUS_REVOKED);
                        pgp_revocation_status_free(rs);
                        if (revoked) {
                            T("TPK %s is revoked.", primary_fpr_str);
                            good = false;
                            cookie->good_but_revoked ++;
                        } else if (! pgp_tpk_alive(tpk)) {
                            T("TPK %s is not alive.", primary_fpr_str);
                            good = false;
                            cookie->good_but_expired ++;
                        }

                        // Same thing for the signing key.
                        if (good) {
                            pgp_tpk_key_iter_t iter = pgp_tpk_key_iter_all(tpk);
                            pgp_key_t key;
                            pgp_signature_t sig;
                            while ((key = pgp_tpk_key_iter_next(iter, &sig, &rs))
                                   && good) {
                                pgp_keyid_t x = pgp_key_keyid(key);
                                if (pgp_keyid_equal(keyid, x)) {
                                    // Found the signing key.  Let's make
                                    // sure it is valid.

                                    revoked = (pgp_revocation_status_variant(rs)
                                               == PGP_REVOCATION_STATUS_REVOKED);
                                    if (revoked) {
                                        T("TPK %s's signing key %s is revoked.",
                                          primary_fpr_str, keyid_str);
                                        good = false;
                                        cookie->good_but_revoked ++;
                                    } else if (! pgp_signature_key_alive(sig, key)) {
                                        T("TPK %s's signing key %s is expired.",
                                          primary_fpr_str, keyid_str);
                                        good = false;
                                        cookie->good_but_expired ++;
                                    }
                                }
                                pgp_keyid_free(x);
                                pgp_revocation_status_free(rs);
                                pgp_signature_free(sig);
                                pgp_key_free(key);
                            }
                            pgp_tpk_key_iter_free(iter);
                        }

                        if (good) {
                            stringlist_add_unique(cookie->signer_keylist,
                                                  primary_fpr_str);

                            T("Good signature from %s", primary_fpr_str);

                            cookie->good_checksums ++;
                        }

                        free(primary_fpr_str);
                        pgp_fingerprint_free(primary_fpr);
                        pgp_tpk_free(tpk);
                    } else {
                        // If we get
                        // PGP_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM,
                        // then the TPK should be available.  But,
                        // another process could have deleted the key
                        // from the store in the mean time, so be
                        // tolerant.
                        T("Key to check signature from %s disappeared",
                          keyid_str);
                        cookie->missing_keys ++;
                    }
                    break;

                case PGP_VERIFICATION_RESULT_MISSING_KEY:
                    pgp_verification_result_missing_key (result, &sig);
                    keyid = pgp_signature_issuer (sig);
                    keyid_str = pgp_keyid_to_string (keyid);
                    T("No key to check signature from %s", keyid_str);

                    cookie->missing_keys ++;
                    break;

                case PGP_VERIFICATION_RESULT_BAD_CHECKSUM:
                    pgp_verification_result_bad_checksum (result, &sig);
                    keyid = pgp_signature_issuer (sig);
                    if (keyid) {
                        keyid_str = pgp_keyid_to_string (keyid);
                        T("Bad signature from %s", keyid_str);
                    } else {
                        T("Bad signature without issuer information");
                    }

                    cookie->bad_checksums ++;
                    break;

                default:
                    assert (! "reachable");
                }

            eol:
                free (keyid_str);
                pgp_signature_free (sig);
                pgp_verification_result_free (result);
            }
            pgp_verification_result_iter_free (results);
            break;

        default:
            assert (! "reachable");
        }

        pgp_message_layer_free (layer);
    }

    pgp_message_structure_iter_free (iter);
    pgp_message_structure_free (structure);

    return PGP_STATUS_SUCCESS;
}

static pgp_status_t inspect_cb(
    void *cookie_opaque, pgp_packet_parser_t pp)
{
    struct decrypt_cookie *cookie = cookie_opaque;

    pgp_packet_t packet = pgp_packet_parser_packet(pp);
    assert(packet);

    pgp_tag_t tag = pgp_packet_tag(packet);

    T("%s", pgp_tag_to_string(tag));

    if (tag == PGP_TAG_LITERAL) {
        pgp_literal_t literal = pgp_packet_ref_literal(packet);
        cookie->filename = pgp_literal_filename(literal);
        pgp_literal_free(literal);
    }

    pgp_packet_free(packet);

    return 0;
}

PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct decrypt_cookie cookie = { session, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, NULL };
    pgp_reader_t reader = NULL;
    pgp_writer_t writer = NULL;
    pgp_reader_t decryptor = NULL;
    *ptext = NULL;
    *psize = 0;

    // XXX: We don't yet handle detached signatures over encrypted
    // messages.
    assert(!dsigtext);

    cookie.recipient_keylist = new_stringlist(NULL);
    if (!cookie.recipient_keylist)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "recipient_keylist");

    cookie.signer_keylist = new_stringlist(NULL);
    if (!cookie.signer_keylist)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "signer_keylist");

    reader = pgp_reader_from_bytes((const uint8_t *) ctext, csize);
    if (! reader)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "Creating reader");

    writer = pgp_writer_alloc((void **) ptext, psize);
    if (! writer)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR, "Creating writer");

    pgp_error_t err = NULL;
    decryptor = pgp_decryptor_new(&err, reader,
                                  get_public_keys_cb, decrypt_cb,
                                  check_signatures_cb, inspect_cb,
                                  &cookie, 0);
    if (! decryptor)
        ERROR_OUT(err, PEP_DECRYPT_NO_KEY, "pgp_decryptor_new");

    // Copy 128 MB at a time.
    ssize_t nread;
    while ((nread = pgp_reader_copy (&err, decryptor, writer,
                                     128 * 1024 * 1024) > 0))
        ;
    if (nread < 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "pgp_reader_read");

    // Add a terminating NUL for naive users
    pgp_writer_write(&err, writer, (const uint8_t *) &""[0], 1);

    if (! cookie.decrypted)
        ERROR_OUT(err, PEP_DECRYPT_NO_KEY, "Decryption failed");

    if (! cookie.signer_keylist) {
        cookie.signer_keylist = new_stringlist("");
        if (! cookie.signer_keylist)
            ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "cookie.signer_keylist");
    }
    if (!cookie.signer_keylist->value)
        stringlist_add(cookie.signer_keylist, "");

    *keylist = cookie.signer_keylist;
    stringlist_append(*keylist, cookie.recipient_keylist);

    if (filename_ptr)
        *filename_ptr = cookie.filename;

 out:
    if (status == PEP_STATUS_OK) {
        // **********************************
        // Sync changes with pgp_verify_text.
        // **********************************

        if (cookie.good_checksums) {
            // If there is at least one signature that we can verify,
            // succeed.
            status = PEP_DECRYPTED_AND_VERIFIED;
        } else if (cookie.good_but_revoked) {
            // If there are any signatures from revoked keys, fail.
            status = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
        } else if (cookie.bad_checksums) {
            // If there are any bad signatures, fail.
            status = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
        } else if (cookie.good_but_expired) {
            // If there are any signatures from expired keys, fail.
            status = PEP_DECRYPTED;
        } else {
            // We couldn't verify any signatures (possibly because we
            // don't have the keys).
            status = PEP_DECRYPTED;
        }
    } else {
        free_stringlist(cookie.recipient_keylist);
        free_stringlist(cookie.signer_keylist);
        free(cookie.filename);
        free(*ptext);
    }

    pgp_reader_free(reader);
    pgp_reader_free(decryptor);
    pgp_writer_free(writer);

    T("-> %s", pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    struct decrypt_cookie cookie = { session, 0, NULL, NULL, 0, 0, 0, };
    pgp_reader_t reader = NULL;
    pgp_reader_t dsig_reader = NULL;
    pgp_reader_t verifier = NULL;

    if (size == 0 || sig_size == 0)
        return PEP_DECRYPT_WRONG_FORMAT;

#if TRACING > 0
    {
        int cr = 0;
        int crlf = 0;
        int lf = 0;

        for (int i = 0; i < size; i ++) {
            // CR
            if (text[i] == '\r') {
                cr ++;
            }
            // LF
            if (text[i] == '\n') {
                if (i > 0 && text[i - 1] == '\r') {
                    cr --;
                    crlf ++;
                } else {
                    lf ++;
                }
            }
        }

        T("Text to verify: %zd bytes with %d crlfs, %d bare crs and %d bare lfs",
          size, crlf, cr, lf);
    }
#endif

    cookie.recipient_keylist = new_stringlist(NULL);
    if (!cookie.recipient_keylist)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    cookie.signer_keylist = new_stringlist(NULL);
    if (!cookie.signer_keylist)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    reader = pgp_reader_from_bytes((const uint8_t *) text, size);
    if (! reader)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "Creating reader");

    dsig_reader = NULL;
    if (signature) {
        dsig_reader = pgp_reader_from_bytes((uint8_t *) signature, sig_size);
        if (! dsig_reader)
            ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "Creating signature reader");
    }

    if (dsig_reader)
        verifier = pgp_detached_verifier_new(&err, dsig_reader, reader,
                                             get_public_keys_cb,
                                             check_signatures_cb,
                                             &cookie, 0);
    else
        verifier = pgp_verifier_new(&err, reader,
                                    get_public_keys_cb,
                                    check_signatures_cb,
                                    &cookie, 0);
    if (! verifier)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Creating verifier");
    if (pgp_reader_discard(&err, verifier) < 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "verifier");

    if (! cookie.signer_keylist) {
        cookie.signer_keylist = new_stringlist("");
        if (! cookie.signer_keylist)
            ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "cookie.signer_keylist");
    }
    if (!cookie.signer_keylist->value)
        stringlist_add(cookie.signer_keylist, "");

    *keylist = cookie.signer_keylist;
    stringlist_append(*keylist, cookie.recipient_keylist);

 out:
    if (status == PEP_STATUS_OK) {
        // *****************************************
        // Sync changes with pgp_decrypt_and_verify.
        // *****************************************

        if (cookie.good_but_expired) {
            // If there are any signatures from expired keys, fail.
            status = PEP_UNENCRYPTED;
        } else if (cookie.good_but_revoked) {
            // If there are any signatures from revoked keys, fail.
            status = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
        } else if (cookie.bad_checksums) {
            // If there are any bad signatures, fail.
            status = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
        } else if (cookie.good_checksums) {
            // If there is at least one signature that we can verify,
            // succeed.
            status = PEP_VERIFIED;
        } else {
            // We couldn't verify any signatures (possibly because we
            // don't have the keys).
            status = PEP_UNENCRYPTED;
        }
    } else {
        free_stringlist(cookie.recipient_keylist);
        free_stringlist(cookie.signer_keylist);
    }

    pgp_reader_free(verifier);
    pgp_reader_free(reader);
    pgp_reader_free(dsig_reader);

    T("-> %s", pEp_status_to_string(status));
    return status;
}


PEP_STATUS pgp_sign_only(
    PEP_SESSION session, const char* fpr, const char *ptext,
    size_t psize, char **stext, size_t *ssize)
{
    assert(session);
    assert(fpr && fpr[0]);
    assert(ptext);
    assert(psize);
    assert(stext);
    assert(ssize);
    *stext = NULL;
    *ssize = 0;

    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t signer_tpk = NULL;
    pgp_tpk_key_iter_t iter = NULL;
    pgp_key_pair_t signing_keypair = NULL;
    pgp_signer_t signer = NULL;
    pgp_writer_stack_t ws = NULL;

    status = tpk_find_by_fpr_hex(session, fpr, true, &signer_tpk, NULL);
    ERROR_OUT(NULL, status, "Looking up key '%s'", fpr);

    iter = pgp_tpk_key_iter_valid(signer_tpk);
    pgp_tpk_key_iter_signing_capable (iter);
    pgp_tpk_key_iter_unencrypted_secret (iter, true);

    // If there are multiple signing capable subkeys, we just take
    // the first one, whichever one that happens to be.
    pgp_key_t key = pgp_tpk_key_iter_next (iter, NULL, NULL);
    if (! key)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR,
                   "%s has no signing capable key", fpr);

    signing_keypair = pgp_key_into_key_pair (NULL, pgp_key_clone (key));
    if (! signing_keypair)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a keypair");

    signer = pgp_key_pair_as_signer (signing_keypair);
    if (! signer)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a signer");


    pgp_writer_t writer = pgp_writer_alloc((void **) stext, ssize);
    writer = pgp_armor_writer_new(&err, writer,
                                  PGP_ARMOR_KIND_MESSAGE, NULL, 0);
    if (!writer)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up armor writer");

    ws = pgp_writer_stack_message(writer);

    ws = pgp_signer_new_detached(&err, ws, &signer, 1, 0);
    if (!ws)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up signer");

    pgp_status_t write_status =
        pgp_writer_stack_write_all (&err, ws,
                                    (uint8_t *) ptext, psize);
    if (write_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Encrypting message");

    pgp_status_t pgp_status = pgp_writer_stack_finalize (&err, ws);
    ws = NULL;
    if (pgp_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Flushing writer");

    // Add a terminating NUL for naive users
    void *t = realloc(*stext, *ssize + 1);
    if (! t)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");
    *stext = t;
    (*stext)[*ssize] = 0;

 out:
    pgp_signer_free (signer);
    pgp_key_pair_free (signing_keypair);
    pgp_tpk_key_iter_free (iter);
    pgp_tpk_free(signer_tpk);

    T("(%s)-> %s", fpr, pEp_status_to_string(status));
    return status;
}

static PEP_STATUS pgp_encrypt_sign_optional(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize, bool sign)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    int keys_count = 0;
    pgp_tpk_t *keys = NULL;
    pgp_tpk_t signer_tpk = NULL;
    pgp_writer_stack_t ws = NULL;
    pgp_tpk_key_iter_t iter = NULL;
    pgp_key_pair_t signing_keypair = NULL;
    pgp_signer_t signer = NULL;

    assert(session);
    assert(keylist);
    assert(ptext);
    assert(psize);
    assert(ctext);
    assert(csize);

    *ctext = NULL;
    *csize = 0;

    keys = calloc(stringlist_length(keylist), sizeof(*keys));
    if (keys == NULL)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    // Get the keys for the recipients.
    const stringlist_t *_keylist;
    for (_keylist = keylist; _keylist != NULL; _keylist = _keylist->next) {
        assert(_keylist->value);
        pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(_keylist->value);
        status = tpk_find_by_fpr(session, pgp_fpr, false, &keys[keys_count ++], NULL);
        pgp_fingerprint_free(pgp_fpr);
        ERROR_OUT(NULL, status, "Looking up key for recipient '%s'", _keylist->value);
    }

    if (sign) {
        // The first key in the keylist is the signer.
        status = tpk_find_by_fpr_hex(session, keylist->value, true, &signer_tpk, NULL);
        ERROR_OUT(NULL, status, "Looking up key for signing '%s'", keylist->value);
    }

    pgp_writer_t writer_alloc = pgp_writer_alloc((void **) ctext, csize);
    pgp_writer_t writer = pgp_armor_writer_new(&err, writer_alloc,
                                  PGP_ARMOR_KIND_MESSAGE, NULL, 0);
    if (!writer)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up armor writer");

    ws = pgp_writer_stack_message(writer);
    ws = pgp_encryptor_new (&err, ws,
                            NULL, 0, keys, keys_count,
                            PGP_ENCRYPTION_MODE_FOR_TRANSPORT, 0);
    if (!ws)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up encryptor");

    if (sign) {
        iter = pgp_tpk_key_iter_valid(signer_tpk);
        pgp_tpk_key_iter_signing_capable (iter);
        pgp_tpk_key_iter_unencrypted_secret (iter, true);

        // If there are multiple signing capable subkeys, we just take
        // the first one, whichever one that happens to be.
        pgp_key_t key = pgp_tpk_key_iter_next (iter, NULL, NULL);
        if (! key)
            ERROR_OUT (err, PEP_UNKNOWN_ERROR,
                       "%s has no signing capable key", keylist->value);

        signing_keypair = pgp_key_into_key_pair (NULL, pgp_key_clone (key));
        if (! signing_keypair)
            ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a keypair");

        signer = pgp_key_pair_as_signer (signing_keypair);
        if (! signer)
            ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a signer");

        ws = pgp_signer_new(&err, ws, &signer, 1, 0);
        if (!ws)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up signer");
    }

    ws = pgp_literal_writer_new (&err, ws);
    if (!ws)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up literal writer");

    pgp_status_t write_status =
        pgp_writer_stack_write_all (&err, ws,
                                    (uint8_t *) ptext, psize);
    if (write_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Encrypting message");

    pgp_status_t pgp_status = pgp_writer_stack_finalize (&err, ws);
    ws = NULL;
    if (pgp_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Flushing writer");

    pgp_writer_free (writer_alloc);

    // Add a terminating NUL for naive users
    void *t = realloc(*ctext, *csize + 1);
    if (! t) {
        free(*ctext);
        *ctext = NULL;
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");
    }
    *ctext = t;
    (*ctext)[*csize] = 0;

 out:
    pgp_signer_free (signer);
    pgp_key_pair_free (signing_keypair);
    pgp_tpk_key_iter_free (iter);
    pgp_tpk_free(signer_tpk);

    for (int i = 0; i < keys_count; i ++)
        pgp_tpk_free(keys[i]);
    free(keys);

    T("-> %s", pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_encrypt_only(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize)
{
    return pgp_encrypt_sign_optional(session, keylist, ptext,
        psize, ctext, csize, false);
}

PEP_STATUS pgp_encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize)
{
    return pgp_encrypt_sign_optional(session, keylist, ptext,
        psize, ctext, csize, true);
}


PEP_STATUS pgp_generate_keypair(PEP_SESSION session, pEp_identity *identity)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_packet_t userid_packet = NULL;
    char *userid = NULL;
    pgp_tpk_t tpk = NULL;
    pgp_fingerprint_t pgp_fpr = NULL;
    char *fpr = NULL;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL || identity->fpr[0] == 0);
    assert(identity->username);

    userid_packet = pgp_user_id_from_unchecked_address(&err,
                                                       identity->username, NULL,
                                                       identity->address);
    if (!userid_packet)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "pgp_user_id_from_other_address");

    size_t userid_len = 0;
    const uint8_t *raw = pgp_user_id_value(userid_packet, &userid_len);

    // NUL terminate it.
    userid = malloc(userid_len + 1);
    if (!userid)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    memcpy(userid, raw, userid_len);
    userid[userid_len] = 0;

    T("(%s)", userid);

    // Generate a key.
    pgp_tpk_builder_t tpkb = pgp_tpk_builder_general_purpose(
        cipher_suite(session->cipher_suite), userid);
    pgp_signature_t rev;
    if (pgp_tpk_builder_generate(&err, tpkb, &tpk, &rev))
        ERROR_OUT(err, PEP_CANNOT_CREATE_KEY, "Generating a key pair");

    // XXX: We should return this.
    pgp_signature_free(rev);

    // Get the fingerprint.
    pgp_fpr = pgp_tpk_fingerprint(tpk);
    fpr = pgp_fingerprint_to_hex(pgp_fpr);

    status = tpk_save(session, tpk, NULL);
    tpk = NULL;
    if (status != 0)
        ERROR_OUT(NULL, PEP_CANNOT_CREATE_KEY, "saving TSK");

    free(identity->fpr);
    identity->fpr = fpr;
    fpr = NULL;

 out:
    pgp_fingerprint_free(pgp_fpr);
    free(fpr);
    pgp_tpk_free(tpk);
    free(userid);
    pgp_packet_free(userid_packet);

    T("-> %s", pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr_raw)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session && fpr_raw && fpr_raw[0]);
    if (!(session && fpr_raw && fpr_raw[0]))
        ERROR_OUT(NULL, PEP_ILLEGAL_VALUE, "invalid arguments");

    char *fpr = pgp_fingerprint_canonicalize(fpr_raw);
    if (! fpr)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    T("Deleting %s", fpr);

    sqlite3_stmt *stmt = session->sq_sql.delete_keypair;
    sqlite3_bind_text(stmt, 1, fpr, -1, free);

    int sqlite_result = Sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (sqlite_result != SQLITE_DONE)
        ERROR_OUT(NULL, PEP_CANNOT_DELETE_KEY,
                  "deletion failed: %s", sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_changes(session->key_db);
    assert(sqlite_result >= 0 && sqlite_result < 2);
    if (sqlite_result < 1)
        ERROR_OUT(NULL, PEP_KEY_NOT_FOUND,
                  "attempt to delete non-existent key: %s", fpr_raw);

 out:
    return status;
}

static unsigned int count_keydata_parts(const char* key_data, size_t size) {
    unsigned int retval = 0;
    
    const char* pgp_begin = "-----BEGIN PGP";
    size_t prefix_len = strlen(pgp_begin);
    size_t size_remaining = size;
    
    while (key_data) {
        if (size_remaining <= prefix_len || key_data[0] == '\0')
            break;
        key_data = strnstr(key_data, pgp_begin, size_remaining);
        if (key_data) {
            retval++;
            key_data += prefix_len;
            size_remaining -= prefix_len;
        }
    }
    return retval;
 }

PEP_STATUS _pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents)
{
    PEP_STATUS status = PEP_NO_KEY_IMPORTED;
    pgp_error_t err;
    pgp_tpk_parser_t parser = NULL;

    if (private_idents)
        *private_idents = NULL;

    T("parsing %zd bytes", size);

    pgp_packet_parser_result_t ppr
        = pgp_packet_parser_from_bytes(&err, (uint8_t *) key_data, size);
    if (! ppr)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Creating packet parser");

    pgp_tag_t tag = pgp_packet_parser_result_tag(ppr);
    switch (tag) {
    case PGP_TAG_SIGNATURE: {
        // The following asserts can't fail, because
        // pgp_packet_parser_result_tag succeeded and the tag is
        // right.
        pgp_packet_parser_t pp = pgp_packet_parser_result_packet_parser (ppr);
        assert(pp);

        pgp_packet_t packet = NULL;
        if (pgp_packet_parser_next(&err, pp, &packet, &ppr))
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Getting signature packet");

        pgp_signature_t sig = pgp_packet_ref_signature (packet);
        assert(sig);

        pgp_tpk_t tpk = NULL;

        pgp_fingerprint_t issuer_fpr = pgp_signature_issuer_fingerprint(sig);
        if (issuer_fpr) {
            char *issuer_fpr_hex = pgp_fingerprint_to_hex(issuer_fpr);
            T("Importing a signature issued by %s", issuer_fpr_hex);

            status = tpk_find_by_fpr_hex(session, issuer_fpr_hex,
                                         false, &tpk, NULL);
            if (status && status != PEP_KEY_NOT_FOUND)
                DUMP_ERR(NULL, status, "Looking up %s", issuer_fpr_hex);

            free(issuer_fpr_hex);
            pgp_fingerprint_free(issuer_fpr);
        }

        if (! tpk) {
            pgp_keyid_t issuer = pgp_signature_issuer(sig);
            if (issuer) {
                char *issuer_hex = pgp_keyid_to_hex(issuer);
                T("Importing a signature issued by %s", issuer_hex);

                status = tpk_find_by_keyid_hex(session, issuer_hex,
                                               false, &tpk, NULL);
                if (status && status != PEP_KEY_NOT_FOUND)
                    DUMP_ERR(NULL, status, "Looking up %s", issuer_hex);

                free(issuer_hex);
                pgp_keyid_free(issuer);
            }
        }

        // We need a packet.  sig is only a reference, so we just need
        // to free it.
        pgp_signature_free(sig);

        if (tpk) {
            T("Merging packet: %s", pgp_packet_debug(packet));

            tpk = pgp_tpk_merge_packets (&err, tpk, &packet, 1);
            if (! tpk)
                ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Merging signature");

            status = tpk_save(session, tpk, NULL);
            if (status)
                ERROR_OUT(NULL, status, "saving merged TPK");
            status = PEP_KEY_IMPORTED;
        }
        break;
    }
    case PGP_TAG_PUBLIC_KEY:
    case PGP_TAG_SECRET_KEY: {
        parser = pgp_tpk_parser_from_packet_parser(ppr);
        pgp_tpk_t tpk;
        int count = 0;
        err = NULL;
        while ((tpk = pgp_tpk_parser_next(&err, parser))) {
            count ++;

            T("#%d. TPK for %s, %s",
              count, pgp_tpk_primary_user_id(tpk),
              pgp_fingerprint_to_hex(pgp_tpk_fingerprint(tpk)));

            // If private_idents is not NULL and there is any private key
            // material, it will be saved.
            status = tpk_save(session, tpk, private_idents);
            if (status == PEP_STATUS_OK)
                status = PEP_KEY_IMPORTED;
            else
                ERROR_OUT(NULL, status, "saving TPK");
        }
        if (err || count == 0)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "parsing key data");
        break;
    }
    default:
        ERROR_OUT(NULL, PEP_NO_KEY_IMPORTED,
                  "Can't import %s", pgp_tag_to_string(tag));
        break;
    }

    int int_result = sqlite3_exec(
        session->key_db,
        "PRAGMA wal_checkpoint(FULL);\n"
        ,
        NULL,
        NULL,
        NULL
    );
    if (int_result != SQLITE_OK)
        status = PEP_UNKNOWN_DB_ERROR;

 out:
    pgp_tpk_parser_free(parser);

    T("-> %s", pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents)
{
    unsigned int keycount = count_keydata_parts(key_data, size);
    if (keycount < 2)
        return(_pgp_import_keydata(session, key_data, size, private_idents));

    const char* pgp_begin = "-----BEGIN PGP";
    size_t prefix_len = strlen(pgp_begin);
        
    unsigned int i;
    const char* curr_begin;
    size_t curr_size;
    
    identity_list* collected_idents = NULL;        
    
    PEP_STATUS retval = PEP_KEY_IMPORTED;
    
    for (i = 0, curr_begin = key_data; i < keycount; i++) {
        const char* next_begin = NULL;

        // This is assured to be OK because the count function above 
        // made sure that THIS round contains at least prefix_len chars
        // We used strnstr to count, so we know that strstr will be ok.
        if (strlen(curr_begin + prefix_len) > prefix_len)
            next_begin = strstr(curr_begin + prefix_len, pgp_begin);

        if (next_begin)
            curr_size = next_begin - curr_begin;
        else
            curr_size = (key_data + size) - curr_begin;
        
        PEP_STATUS curr_status = _pgp_import_keydata(session, curr_begin, curr_size, private_idents);
        if (private_idents && *private_idents) {
            if (!collected_idents)
                collected_idents = *private_idents;
            else 
                identity_list_join(collected_idents, *private_idents);
            *private_idents = NULL;    
        }
        
        if (curr_status != retval) {
            switch (curr_status) {
                case PEP_NO_KEY_IMPORTED:
                case PEP_KEY_NOT_FOUND:
                case PEP_UNKNOWN_ERROR:
                    switch (retval) {
                        case PEP_KEY_IMPORTED:
                            retval = PEP_SOME_KEYS_IMPORTED;
                            break;
                        case PEP_UNKNOWN_ERROR:
                            retval = curr_status;
                            break;
                        default:
                            break;
                    }
                    break;
                case PEP_KEY_IMPORTED:
                    retval = PEP_SOME_KEYS_IMPORTED;
                default:
                    break;
            }        
        }        
        curr_begin = next_begin;     
    }
    
    if (private_idents)
        *private_idents = collected_idents;
    
    return retval;    
}

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t tpk = NULL;
    pgp_writer_t armor_writer = NULL;
    pgp_writer_t memory_writer = NULL;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(*key_data == NULL);
    assert(size);

    *size = 0;

    T("(%s, %s)", fpr, secret ? "secret" : "public");

    // If the caller asks for a secret key and we only have a
    // public key, then we return an error.
    status = tpk_find_by_fpr_hex(session, fpr, secret, &tpk, NULL);
    ERROR_OUT(NULL, status, "Looking up TSK for %s", fpr);

    memory_writer = pgp_writer_alloc((void **) key_data, size);
    if (! memory_writer)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR, "creating memory writer");
    armor_writer = pgp_armor_writer_new(&err, memory_writer,
                                        PGP_ARMOR_KIND_PUBLICKEY, NULL, 0);
    if (! armor_writer) {
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "creating armored writer");
    }

    if (secret) {
        pgp_tsk_t tsk = pgp_tpk_as_tsk(tpk);
        if (pgp_tsk_serialize(&err, tsk, armor_writer))
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "serializing TSK");
        pgp_tsk_free(tsk);
    } else {
        if (pgp_tpk_serialize(&err, tpk, armor_writer))
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "serializing TPK");
    }

 out:
    if (armor_writer)
        pgp_writer_free(armor_writer);

    if (memory_writer) {
        if (status == PEP_STATUS_OK) {
            // Add a trailing NUL.
            pgp_writer_write(NULL, memory_writer, (const uint8_t *) "", 1);
        }

        pgp_writer_free(memory_writer);
    }

    if (tpk)
        pgp_tpk_free(tpk);

    (*size)--;  // Sequoia is delivering the 0 byte at the end with size, but
                // pEp is expecting it without
    T("(%s) -> %s", fpr, pEp_status_to_string(status));
    return status;
}

static char *_undot_address(const char* address) {
    if (!address)
        return NULL;

    int addr_len = strlen(address);
    const char* at = memchr(address, '@', addr_len);

    if (!at)
        at = address + addr_len;

    char* retval = calloc(1, addr_len + 1);

    const char* addr_curr = address;
    char* retval_curr = retval;

    while (addr_curr < at) {
        if (*addr_curr == '.') {
            addr_curr++;
            continue;
        }
        *retval_curr = *addr_curr;
        retval_curr++;
        addr_curr++;
    }
    if (*addr_curr == '@')
        strcat(retval_curr, addr_curr);

    return retval;
}

static stringpair_list_t *add_key(PEP_SESSION session,
                                  stringpair_list_t *keyinfo_list,
                                  stringlist_t* keylist,
                                  pgp_tpk_t tpk, pgp_fingerprint_t fpr) {
    bool revoked = false;
    // Don't add revoked keys to the keyinfo_list.
    if (keyinfo_list) {
        pgp_revocation_status_t rs = pgp_tpk_revocation_status(tpk);
        pgp_revocation_status_variant_t rsv = pgp_revocation_status_variant(rs);
        pgp_revocation_status_free(rs);
        if (rsv == PGP_REVOCATION_STATUS_REVOKED)
            revoked = true;
    }

    if (revoked && ! keylist)
        return keyinfo_list;

    int dealloc_fpr = 0;
    if (!fpr) {
        dealloc_fpr = 1;
        fpr = pgp_tpk_fingerprint(tpk);
    }
    char *fpr_str = pgp_fingerprint_to_hex(fpr);

    if (!revoked && keyinfo_list) {
        char *user_id = pgp_tpk_primary_user_id(tpk);
        if (user_id)
            keyinfo_list = stringpair_list_add(keyinfo_list,
                                               new_stringpair(fpr_str, user_id));
        free(user_id);
    }

    if (keylist)
        keylist = stringlist_add(keylist, fpr_str);

    free(fpr_str);
    if (dealloc_fpr)
        pgp_fingerprint_free(fpr);

    return keyinfo_list;
}

static PEP_STATUS list_keys(PEP_SESSION session,
                            const char* pattern, int private_only,
                            stringpair_list_t** keyinfo_list, stringlist_t** keylist)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_tpk_t tpk = NULL;
    pgp_fingerprint_t fpr = NULL;

    T("('%s', private: %d)", pattern, private_only);

    stringpair_list_t* _keyinfo_list = NULL;
    if (keyinfo_list) {
        _keyinfo_list = new_stringpair_list(NULL);
        if (!_keyinfo_list)
            ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "new_stringpair_list");
    }
    stringlist_t* _keylist = NULL;
    if (keylist) {
        _keylist = new_stringlist(NULL);
        if (!_keylist)
            ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "new_string_list");
    }

    // Trim any leading space.  This also makes it easier to recognize
    // a string that is only whitespace.
    while (*pattern == ' ')
        pattern ++;

    if (strchr(pattern, '@')) {
        // Looks like a mailbox.
        pgp_tpk_t *tpks = NULL;
        int count = 0;
        status = tpk_find_by_email(session, pattern, private_only, &tpks, &count);
        ERROR_OUT(NULL, status, "Looking up '%s'", pattern);
        for (int i = 0; i < count; i ++) {
            add_key(session, _keyinfo_list, _keylist, tpks[i], NULL);
            pgp_tpk_free(tpks[i]);
        }
        free(tpks);

        if (count == 0) {
            // If match failed, check to see if we've got a dotted
            // address in the pattern.  If so, try again without dots.
            const char* dotpos = strstr(pattern, ".");
            const char* atpos = strstr(pattern, "@");
            if (dotpos && atpos && (dotpos < atpos)) {
                char* undotted = _undot_address(pattern);
                if (undotted) {
                    PEP_STATUS status = list_keys(session, undotted, private_only,
                                                  keyinfo_list, keylist);
                    free(undotted);
                    return status;
                }
            }
        }
    } else if (// Only hex characters and spaces
               pattern[strspn(pattern, "0123456789aAbBcCdDeEfF ")] == 0
               // And a fair amount of them.
               && strlen(pattern) >= 16) {
        // Fingerprint.  Note: the pep engine never looks keys up by
        // keyid, so we don't handle them.
        fpr = pgp_fingerprint_from_hex(pattern);
        status = tpk_find_by_fpr(session, fpr, false, &tpk, NULL);
        ERROR_OUT(NULL, status, "Looking up key");
        add_key(session, _keyinfo_list, _keylist, tpk, fpr);
    } else if (pattern[0] == 0) {
        // Empty string.

        pgp_tpk_t *tpks = NULL;
        int count = 0;
        status = tpk_all(session, private_only, &tpks, &count);
        ERROR_OUT(NULL, status, "Looking up '%s'", pattern);
        for (int i = 0; i < count; i ++) {
            add_key(session, _keyinfo_list, _keylist, tpks[i], NULL);
            pgp_tpk_free(tpks[i]);
        }
        free(tpks);
    } else {
        T("unsupported pattern '%s'", pattern);
    }

 out:
    pgp_tpk_free(tpk);
    pgp_fingerprint_free(fpr);

    if (status == PEP_KEY_NOT_FOUND)
        status = PEP_STATUS_OK;

    if (status != PEP_STATUS_OK || (_keyinfo_list && !_keyinfo_list->value)) {
        free_stringpair_list(_keyinfo_list);
        _keyinfo_list = NULL;
    }
    if (keyinfo_list)
        *keyinfo_list = _keyinfo_list;

    if (status != PEP_STATUS_OK || (_keylist && !_keylist->value)) {
        free_stringlist(_keylist);
        _keylist = NULL;
    }
    if (keylist)
        *keylist = _keylist;

    int len = -1;
    if (keylist)
        len = stringlist_length(*keylist);
    else if (keyinfo_list)
        len = stringpair_list_length(*keyinfo_list);
    T("(%s) -> %s (%d keys)", pattern, pEp_status_to_string(status), len);
    return status;
}

// pattern could be empty, an fpr, or a mailbox.
//
// keyinfo_list is a list of <fpr, openpgp userid> tuples for the
// matching keys.
//
// This function filters out revoked key, but not expired keys.
PEP_STATUS pgp_list_keyinfo(PEP_SESSION session,
                            const char* pattern,
                            stringpair_list_t** keyinfo_list)
{
    return list_keys(session, pattern, false, keyinfo_list, NULL);
}

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    assert(!"pgp_recv_key not implemented");
    return PEP_UNKNOWN_ERROR;
}

// Unlike pgp_list_keyinfo, this function returns revoked keys.
PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist)
{
    return list_keys(session, pattern, false, NULL, keylist);
}

// Unlike pgp_list_keyinfo, this function returns revoked keys.
PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist)
{
    return list_keys(session, pattern, true, NULL, keylist);
}

PEP_STATUS pgp_send_key(PEP_SESSION session, const char *pattern)
{
    assert(!"pgp_send_key not implemented");
    return PEP_UNKNOWN_ERROR;
}


PEP_STATUS pgp_renew_key(
    PEP_SESSION session, const char *fpr, const timestamp *ts)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t tpk = NULL;
    pgp_tpk_key_iter_t iter = NULL;
    pgp_key_pair_t keypair = NULL;
    pgp_signer_t signer = NULL;
    time_t t = mktime((struct tm *) ts);

    T("(%s)", fpr);

    status = tpk_find_by_fpr_hex(session, fpr, true, &tpk, NULL);
    ERROR_OUT(NULL, status, "Looking up '%s'", fpr);

    uint32_t creation_time = pgp_key_creation_time(pgp_tpk_primary(tpk));
    if (creation_time > t)
        // The creation time is after the expiration time!
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                  "creation time can't be after expiration time");

    uint32_t delta = t - creation_time;


    iter = pgp_tpk_key_iter_valid(tpk);
    pgp_tpk_key_iter_certification_capable (iter);
    pgp_tpk_key_iter_unencrypted_secret (iter, true);

    // If there are multiple certification capable subkeys, we just
    // take the first one, whichever one that happens to be.
    pgp_key_t key = pgp_tpk_key_iter_next (iter, NULL, NULL);
    if (! key)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR,
                   "%s has no usable certification capable key", fpr);

    keypair = pgp_key_into_key_pair (NULL, pgp_key_clone (key));
    if (! keypair)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a keypair");

    signer = pgp_key_pair_as_signer (keypair);
    if (! signer)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a signer");

    tpk = pgp_tpk_set_expiry(&err, tpk, signer, delta);
    if (! tpk)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "setting expiration");

    status = tpk_save(session, tpk, NULL);
    tpk = NULL;
    ERROR_OUT(NULL, status, "Saving %s", fpr);

 out:
    pgp_signer_free (signer);
    pgp_key_pair_free (keypair);
    pgp_tpk_key_iter_free (iter);
    pgp_tpk_free(tpk);

    T("(%s) -> %s", fpr, pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_revoke_key(
    PEP_SESSION session, const char *fpr, const char *reason)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t tpk = NULL;
    pgp_tpk_key_iter_t iter = NULL;
    pgp_key_pair_t keypair = NULL;
    pgp_signer_t signer = NULL;

    T("(%s)", fpr);

    status = tpk_find_by_fpr_hex(session, fpr, true, &tpk, NULL);
    ERROR_OUT(NULL, status, "Looking up %s", fpr);

    iter = pgp_tpk_key_iter_valid(tpk);
    pgp_tpk_key_iter_certification_capable (iter);
    pgp_tpk_key_iter_unencrypted_secret (iter, true);

    // If there are multiple certification capable subkeys, we just
    // take the first one, whichever one that happens to be.
    pgp_key_t key = pgp_tpk_key_iter_next (iter, NULL, NULL);
    if (! key)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR,
                   "%s has no usable certification capable key", fpr);

    keypair = pgp_key_into_key_pair (NULL, pgp_key_clone (key));
    if (! keypair)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a keypair");

    signer = pgp_key_pair_as_signer (keypair);
    if (! signer)
        ERROR_OUT (err, PEP_UNKNOWN_ERROR, "Creating a signer");

    tpk = pgp_tpk_revoke_in_place(&err, tpk, signer,
                                  PGP_REASON_FOR_REVOCATION_UNSPECIFIED,
                                  reason);
    if (! tpk)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "setting expiration");

    assert(pgp_revocation_status_variant(pgp_tpk_revocation_status(tpk))
           == PGP_REVOCATION_STATUS_REVOKED);

    status = tpk_save(session, tpk, NULL);
    tpk = NULL;
    ERROR_OUT(NULL, status, "Saving %s", fpr);

 out:
    pgp_signer_free (signer);
    pgp_key_pair_free (keypair);
    pgp_tpk_key_iter_free (iter);
    pgp_tpk_free(tpk);

    T("(%s) -> %s", fpr, pEp_status_to_string(status));
    return status;
}

static void _pgp_key_expired(pgp_tpk_t tpk, const time_t when, bool* expired)
{
    // Is the TPK live?
    *expired = !pgp_tpk_alive_at(tpk, when);

#ifdef TRACING
    {
        char buffer[26];
        time_t now = time(NULL);

        if (when == now || when == now - 1) {
            sprintf(buffer, "now");
        } else {
            struct tm tm;
            gmtime_r(&when, &tm);
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
        }

        T("TPK is %slive as of %s", *expired ? "not " : "", buffer);
    }
#endif
    if (*expired)
        goto out;

    // Are there at least one certification subkey, one signing subkey
    // and one encryption subkey that are live?
    //    int can_certify = 0, can_encrypt = 0, can_sign = 0;
    int can_encrypt = 0, can_sign = 0;

    pgp_tpk_key_iter_t key_iter = pgp_tpk_key_iter_valid(tpk);
    pgp_key_t key;
    pgp_signature_t sig;
    pgp_revocation_status_t rev;
    while ((key = pgp_tpk_key_iter_next(key_iter, &sig, &rev))) {
        if (! sig)
            continue;

        if (pgp_signature_can_encrypt_for_transport(sig)
            || pgp_signature_can_encrypt_at_rest(sig))
            can_encrypt = 1;
        if (pgp_signature_can_sign(sig))
            can_sign = 1;
        // if (pgp_signature_can_certify(sig))
        //     can_certify = 1;

//        if (can_encrypt && can_sign && can_certify)
        if (can_encrypt && can_sign)
            break;
    }
    pgp_tpk_key_iter_free(key_iter);

//    *expired = !(can_encrypt && can_sign && can_certify);
    *expired = !(can_encrypt && can_sign);

    T("Key can%s encrypt, can%s sign, can%s certify => %sexpired",
      can_encrypt ? "" : "not",
      can_sign ? "" : "not",
      // can_certify ? "" : "not",
      *expired ? "" : "not ");
      
out:
    // Er, this might be problematic in terms of internal vs. external in log. FIXME?
    T("(%s) -> %s (expired: %d)", fpr, pEp_status_to_string(status), *expired);
    return;
}
                            
PEP_STATUS pgp_key_expired(PEP_SESSION session, const char *fpr,
                           const time_t when, bool *expired)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_tpk_t tpk = NULL;
    T("(%s)", fpr);

    assert(session);
    assert(fpr);
    assert(expired);

    *expired = false;

    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, pgp_fpr, false, &tpk, NULL);
    pgp_fingerprint_free(pgp_fpr);
    ERROR_OUT(NULL, status, "Looking up %s", fpr);

    _pgp_key_expired(tpk, when, expired);
 out:
    pgp_tpk_free(tpk);
    T("(%s) -> %s (expired: %d)", fpr, pEp_status_to_string(status), *expired);
    return status;
}

PEP_STATUS pgp_key_revoked(PEP_SESSION session, const char *fpr, bool *revoked)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_tpk_t tpk;

    T("(%s)", fpr);

    assert(session);
    assert(fpr);
    assert(revoked);

    *revoked = false;

    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, pgp_fpr, false, &tpk, NULL);
    pgp_fingerprint_free(pgp_fpr);
    ERROR_OUT(NULL, status, "Looking up %s", fpr);

    pgp_revocation_status_t rs = pgp_tpk_revocation_status(tpk);
    *revoked = pgp_revocation_status_variant(rs) == PGP_REVOCATION_STATUS_REVOKED;
    pgp_revocation_status_free (rs);
    pgp_tpk_free(tpk);

 out:
    T("(%s) -> %s", fpr, pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_get_key_rating(
    PEP_SESSION session, const char *fpr, PEP_comm_type *comm_type)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_tpk_t tpk = NULL;

    assert(session);
    assert(fpr);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, pgp_fpr, false, &tpk, NULL);
    pgp_fingerprint_free(pgp_fpr);
    ERROR_OUT(NULL, status, "Looking up key: %s", fpr);

    *comm_type = PEP_ct_OpenPGP_unconfirmed;

    bool expired = false;
    
    // MUST guarantee the same behaviour.
    _pgp_key_expired(tpk, time(NULL), &expired);
    
    if (expired) {
        *comm_type = PEP_ct_key_expired;
        goto out;        
    }
    
    // if (pgp_tpk_expired(tpk)) {
    //     *comm_type = PEP_ct_key_expired;
    //     goto out;
    // }

    pgp_revocation_status_t rs = pgp_tpk_revocation_status(tpk);
    pgp_revocation_status_variant_t rsv = pgp_revocation_status_variant(rs);
    pgp_revocation_status_free(rs);
    if (rsv == PGP_REVOCATION_STATUS_REVOKED) {
        *comm_type = PEP_ct_key_revoked;
        goto out;
    }

    PEP_comm_type best_enc = PEP_ct_no_encryption, best_sign = PEP_ct_no_encryption;
    pgp_tpk_key_iter_t key_iter = pgp_tpk_key_iter_valid(tpk);
    pgp_key_t key;
    pgp_signature_t sig;
    pgp_revocation_status_t rev;
    while ((key = pgp_tpk_key_iter_next(key_iter, &sig, &rev))) {
        if (! sig)
            continue;

        PEP_comm_type curr = PEP_ct_no_encryption;

        int can_enc = pgp_signature_can_encrypt_for_transport(sig)
            || pgp_signature_can_encrypt_at_rest(sig);
        int can_sign = pgp_signature_can_sign(sig);

        pgp_public_key_algo_t pk_algo = pgp_key_public_key_algo(key);
        if (pk_algo == PGP_PUBLIC_KEY_ALGO_RSA_ENCRYPT_SIGN
            || pk_algo == PGP_PUBLIC_KEY_ALGO_RSA_ENCRYPT
            || pk_algo == PGP_PUBLIC_KEY_ALGO_RSA_SIGN) {
            int bits = pgp_key_public_key_bits(key);
            if (bits < 1024)
                curr = PEP_ct_key_too_short;
            else if (bits == 1024)
                curr = PEP_ct_OpenPGP_weak_unconfirmed;
            else
                curr = PEP_ct_OpenPGP_unconfirmed;
        } else {
            curr = PEP_ct_OpenPGP_unconfirmed;
        }

        if (can_enc)
            best_enc = _MAX(best_enc, curr);

        if (can_sign)
            best_sign = _MAX(best_sign, curr);
    }
    pgp_tpk_key_iter_free(key_iter);

    if (best_enc == PEP_ct_no_encryption || best_sign == PEP_ct_no_encryption) {
        *comm_type = PEP_ct_key_b0rken;
        goto out;
    } else {
        *comm_type = _MIN(best_enc, best_sign);
    }

 out:
    pgp_tpk_free(tpk);

    T("(%s) -> %s", fpr, pEp_comm_type_to_string(*comm_type));
    return status;
}


PEP_STATUS pgp_key_created(PEP_SESSION session, const char *fpr, time_t *created)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_tpk_t tpk = NULL;
    T("(%s)", fpr);

    *created = 0;

    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, pgp_fpr, false, &tpk, NULL);
    pgp_fingerprint_free(pgp_fpr);
    ERROR_OUT(NULL, status, "Looking up %s", fpr);

    pgp_key_t k = pgp_tpk_primary(tpk);
    *created = pgp_key_creation_time(k);
    pgp_tpk_free(tpk);

 out:
    T("(%s) -> %s", fpr, pEp_status_to_string(status));
    return status;
}

PEP_STATUS pgp_binary(const char **path)
{
    *path = NULL;
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
                                 bool *has_private)
{
    T("(%s)", fpr);
    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    PEP_STATUS status = tpk_find_by_fpr(session, pgp_fpr, true, NULL, NULL);
    pgp_fingerprint_free(pgp_fpr);
    if (status == PEP_STATUS_OK) {
        *has_private = 1;
    } else if (status == PEP_KEY_NOT_FOUND) {
        *has_private = 0;
        status = PEP_STATUS_OK;
    }
    T("(%s) -> %s, %s",
      fpr, *has_private ? "priv" : "pub", pEp_status_to_string(status));
    return status;
}
