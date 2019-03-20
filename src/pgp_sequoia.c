// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define _GNU_SOURCE 1

#include "platform.h"
#include "pEp_internal.h"
#include "pgp_gpg.h"

#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <error.h>

#include <sqlite3.h>

#include "wrappers.h"

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
#  define _T(...) do {                          \
        fprintf(stderr, ##__VA_ARGS__);         \
    } while (0)
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
#  define DUMP_ERR(__de_err, __de_status, ...) do {             \
    TC(__VA_ARGS__);                                            \
    _T(": ");                                                   \
    if (__de_err) {                                             \
        _T("Sequoia: %s => ", pgp_error_to_string(__de_err));   \
        pgp_error_free(__de_err);                               \
    }                                                           \
    _T("%s\n", pep_status_to_string(__de_status));              \
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

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;

    // Create the home directory.
    char *home_env = getenv("HOME");
    if (!home_env)
        ERROR_OUT(NULL, PEP_INIT_GPGME_INIT_FAILED, "HOME unset");

    // Create the DB and initialize it.
    char *path = NULL;
    asprintf(&path, "%s/.pEp_keys.db", home_env);
    if (!path)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");

    int sqlite_result;
    sqlite_result = sqlite3_open_v2(path,
                                    &session->key_db,
                                    SQLITE_OPEN_READWRITE
                                    | SQLITE_OPEN_CREATE
                                    | SQLITE_OPEN_FULLMUTEX
                                    | SQLITE_OPEN_PRIVATECACHE,
                                    NULL);
    free(path);
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
                                 "   userid TEXT NOT NULL,\n"
                                 "   primary_key TEXT NOT NULL,\n"
                                 "   UNIQUE(userid, primary_key),\n"
                                 "   FOREIGN KEY (primary_key)\n"
                                 "       REFERENCES keys(primary_key)\n"
                                 "     ON DELETE CASCADE\n"
                                 ");\n"
                                 "CREATE INDEX IF NOT EXISTS userids_index\n"
                                 "  ON userids (userid, primary_key)\n",
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

// Splits an OpenPGP user id into its name and email components.  A
// user id looks like:
//
//   Name (comment) <email>
//
// This function takes ownership of user_id!!!
//
// namep and emailp may be NULL if they are not required.
static void user_id_split(char *, char **, char **) __attribute__((nonnull(1)));
static void user_id_split(char *user_id, char **namep, char **emailp)
{
    if (namep)
        *namep = NULL;
    if (emailp)
        *emailp = NULL;

    char *email = strchr(user_id, '<');
    if (email) {
        // NUL terminate the string here so that user_id now points at
        // most to: "Name (comment)"
        *email = 0;

        if (emailp && email[1]) {
            email = email + 1;
            char *end = strchr(email, '>');
            if (end) {
                *end = 0;
                *emailp = strdup(email);
            }
        }
    }

    if (!namep)
        return;

    char *comment = strchr(user_id, '(');
    if (comment)
        *comment = 0;

    // Kill any trailing white space.
    for (size_t l = strlen(user_id); l > 0 && user_id[l - 1] == ' '; l --)
        user_id[l - 1] = 0;

    // Kill any leading whitespace.
    char *start = user_id;
    while (*start == ' ')
        start ++;
    if (start[0])
        *namep = strdup(start);

    free(user_id);
}

// step statement and load the tpk and secret.
static PEP_STATUS key_load(PEP_SESSION, sqlite3_stmt *, pgp_tpk_t *, int *)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS key_load(PEP_SESSION session, sqlite3_stmt *stmt,
                           pgp_tpk_t *tpkp, int *secretp)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_result = sqlite3_step(stmt);
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
    T(" -> %s", pep_status_to_string(status));
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

    T(" -> %s (%d tpks)", pep_status_to_string(status), *tpks_countp);
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
    T("(%s, %d) -> %s", fpr_str, private_only, pep_status_to_string(status));
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
    T("(%s, %d) -> %s", keyid_hex, private_only, pep_status_to_string(status));
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
    T("(%s) -> %s (%d results)", pattern, pep_status_to_string(status), *countp);
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
    pgp_tsk_t tsk = pgp_tpk_into_tsk(tpk);
    pgp_status = pgp_tsk_serialize(&err, tsk, writer);
    tpk = pgp_tsk_into_tpk(tsk);
    //pgp_writer_free(writer);
    if (pgp_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Serializing TPK");


    // Insert the TSK into the DB.
    sqlite3_stmt *stmt = session->sq_sql.begin_transaction;
    int sqlite_result = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (sqlite_result != SQLITE_DONE)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                  "begin transaction failed: %s",
                  sqlite3_errmsg(session->key_db));

    stmt = session->sq_sql.tpk_save_insert_primary;
    sqlite3_bind_text(stmt, 1, fpr, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, is_tsk);
    sqlite3_bind_blob(stmt, 3, tsk_buffer, tsk_buffer_len, SQLITE_STATIC);

    sqlite_result = sqlite3_step(stmt);
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

        sqlite_result = sqlite3_step(stmt);
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
        char *user_id = pgp_user_id_binding_user_id(binding);
        if (!user_id || !*user_id)
            continue;

        // Ignore bindings with a self-revocation certificate, but no
        // self-signature.
        if (!pgp_user_id_binding_selfsig(binding)) {
            free(user_id);
            continue;
        }

        char *name, *email;
        user_id_split(user_id, &name, &email); /* user_id is comsumed.  */
        // XXX: Correctly clean up name and email on error...

        if (email) {
            T("  userid: %s", email);

            sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, fpr, -1, SQLITE_STATIC);

            sqlite_result = sqlite3_step(stmt);
            sqlite3_reset(stmt);

            if (sqlite_result != SQLITE_DONE) {
                pgp_user_id_binding_iter_free(user_id_iter);
                free(name);
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
        free(email);
        free(name);

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
        int sqlite_result = sqlite3_step(stmt);
        sqlite3_reset(stmt);
        if (sqlite_result != SQLITE_DONE)
            ERROR_OUT(NULL, PEP_UNKNOWN_ERROR,
                      status == PEP_STATUS_OK
                      ? "commit failed: %s" : "rollback failed: %s",
                      sqlite3_errmsg(session->key_db));
    }

    T("(%s) -> %s", fpr, pep_status_to_string(status));

    if (user_id_iter)
        pgp_user_id_binding_iter_free(user_id_iter);
    if (key_iter)
        pgp_tpk_key_iter_free(key_iter);
    if (stmt)
      sqlite3_reset(stmt);
    free(tsk_buffer);
    if (tpk)
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
    int missing_keys;
    int bad_checksums;
    int decrypted;
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
        pgp_status_t status
            = tpk_find_by_keyid(session, keyids[i], false, &tpk, NULL);
        if (status == PGP_STATUS_SUCCESS)
            (*tpks)[j ++] = tpk;
    }
    *tpk_len = j;
    return PGP_STATUS_SUCCESS;
}

static pgp_status_t
get_secret_keys_cb(void *cookie_opaque,
                   pgp_pkesk_t *pkesks, size_t pkesk_count,
                   pgp_skesk_t *skesks, size_t skesk_count,
                   pgp_secret_t *secret)
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

        T("Decrypted PKESK for %s", keyid_str);

        *secret = pgp_secret_cached(algo, session_key, session_key_len);
        cookie->decrypted = 1;

    eol:
        free(keyid_str);
        if (key_iter)
            pgp_tpk_key_iter_free(key_iter);
        if (tpk)
            pgp_tpk_free(tpk);
    }

    // Consider wildcard recipients.
    if (wildcards) for (int i = 0; i < pkesk_count && !cookie->decrypted; i ++) {
        pgp_pkesk_t pkesk = pkesks[i];
        pgp_keyid_t keyid = pgp_pkesk_recipient(pkesk); /* Reference. */
        char *keyid_str = pgp_keyid_to_hex(keyid);
        pgp_tpk_key_iter_t key_iter = NULL;

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

                *secret = pgp_secret_cached(algo, session_key, session_key_len);
                cookie->decrypted = 1;
            }

            pgp_tpk_key_iter_free(key_iter);
            key_iter = NULL;
        }
    eol2:
        free(keyid_str);
        if (key_iter)
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
check_signatures_cb(void *cookie_opaque,
                   pgp_verification_results_t results, size_t levels)
{
    struct decrypt_cookie *cookie = cookie_opaque;
    PEP_SESSION session = cookie->session;

    int level;
    for (level = 0; level < levels; level ++) {
        pgp_verification_result_t *vrs;
        size_t vr_count;
        pgp_verification_results_at_level(results, level, &vrs, &vr_count);

        int i;
        for (i = 0; i < vr_count; i ++) {
            pgp_tpk_t tpk = NULL;
            pgp_verification_result_code_t code
                = pgp_verification_result_code(vrs[i]);

            if (code == PGP_VERIFICATION_RESULT_CODE_BAD_CHECKSUM) {
                cookie->bad_checksums ++;
                continue;
            }
            if (code == PGP_VERIFICATION_RESULT_CODE_MISSING_KEY) {
                // No key, nothing we can do.
                cookie->missing_keys ++;
                continue;
            }

            // We need to add the fingerprint of the primary key to
            // cookie->signer_keylist.
            pgp_signature_t sig = pgp_verification_result_signature(vrs[i]);

            // First try looking up by the TPK using the
            // IssuerFingerprint subpacket.
            pgp_fingerprint_t issuer_fp = pgp_signature_issuer_fingerprint(sig);
            if (issuer_fp) {
                pgp_keyid_t issuer = pgp_fingerprint_to_keyid(issuer_fp);
                if (tpk_find_by_keyid(session, issuer, false, &tpk, NULL) != PEP_STATUS_OK)
                    ; // Soft error.  Ignore.
                pgp_keyid_free(issuer);
                pgp_fingerprint_free(issuer_fp);
            }

            // If that is not available, try using the Issuer subpacket.
            if (!tpk) {
                pgp_keyid_t issuer = pgp_signature_issuer(sig);
                if (issuer) {
                    if (tpk_find_by_keyid(session, issuer, false, &tpk, NULL) != PEP_STATUS_OK)
                        ; // Soft error.  Ignore.
                }
                pgp_keyid_free(issuer);
            }

            if (tpk) {
                // Ok, we have a TPK.
                pgp_fingerprint_t fp = pgp_tpk_fingerprint(tpk);
                char *fp_str = pgp_fingerprint_to_hex(fp);
                stringlist_add_unique(cookie->signer_keylist, fp_str);

                // XXX: Check that the TPK and the key used to make
                // the signature and the signature itself are alive
                // and not revoked.  Revoked =>
                // PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH; Expired key
                // or sig => PEP_DECRYPTED.
                cookie->good_checksums ++;

                free(fp_str);
                pgp_fingerprint_free(fp);
                pgp_tpk_free(tpk);
            } else {
                // If we get
                // PGP_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM, then the
                // TPK should be available.  But, another process
                // could have deleted the key from the store in the
                // mean time, so be tolerant.
                cookie->missing_keys ++;
            }
        }
    }

    return PGP_STATUS_SUCCESS;
}

PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct decrypt_cookie cookie = { session, 0, NULL, NULL, 0, 0, 0, };
    pgp_reader_t reader = NULL;
    pgp_writer_t writer = NULL;
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
    pgp_status_t pgp_status
        = pgp_decrypt(&err, reader, writer,
                      get_public_keys_cb, get_secret_keys_cb,
                      check_signatures_cb, &cookie);
    if (pgp_status)
        ERROR_OUT(err, PEP_DECRYPT_NO_KEY, "pgp_decrypt");

    if (! cookie.decrypted)
        ERROR_OUT(err, PEP_DECRYPT_NO_KEY, "Decryption failed");

    // Add a terminating NUL for naive users
    void *t = realloc(*ptext, *psize + 1);
    if (! t)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");
    *ptext = t;
    (*ptext)[*psize] = 0;

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
        if (cookie.bad_checksums) {
            // If there are any bad signatures, fail.
            status = PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH;
        } else if (cookie.good_checksums) {
            // If there is at least one signature that we can verify,
            // succeed.
            status = PEP_DECRYPTED_AND_VERIFIED;
        } else {
            // We couldn't verify any signatures (possibly because we
            // don't have the keys).
            status = PEP_DECRYPTED;
        }
    } else {
        free_stringlist(cookie.recipient_keylist);
        free_stringlist(cookie.signer_keylist);
        free(*ptext);
    }

    if (reader)
        pgp_reader_free(reader);
    if (writer)
        pgp_writer_free(writer);

    T("-> %s", pep_status_to_string(status));
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

    if (size == 0 || sig_size == 0)
        return PEP_DECRYPT_WRONG_FORMAT;

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

    if (pgp_verify(&err, reader, dsig_reader, /* output */ NULL,
                  get_public_keys_cb, check_signatures_cb, &cookie))
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "pgp_verify");

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
        if (cookie.bad_checksums) {
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

    if (reader)
        pgp_reader_free(reader);
    if (dsig_reader)
        pgp_reader_free(dsig_reader);

    T("-> %s", pep_status_to_string(status));
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
    pgp_tpk_t signer = NULL;
    pgp_writer_stack_t ws = NULL;

    status = tpk_find_by_fpr_hex(session, fpr, true, &signer, NULL);
    ERROR_OUT(NULL, status, "Looking up key '%s'", fpr);

    pgp_writer_t writer = pgp_writer_alloc((void **) stext, ssize);
    writer = pgp_armor_writer_new(&err, writer,
                                  PGP_ARMOR_KIND_MESSAGE, NULL, 0);
    if (!writer)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up armor writer");

    ws = pgp_writer_stack_message(writer);

    ws = pgp_signer_new_detached(&err, ws, &signer, 1);
    if (!ws)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up signer");

    pgp_status_t write_status =
        pgp_writer_stack_write_all (&err, ws,
                                    (uint8_t *) ptext, psize);
    if (write_status != 0)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Encrypting message");

    // Add a terminating NUL for naive users
    void *t = realloc(*stext, *ssize + 1);
    if (! t)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");
    *stext = t;
    (*stext)[*ssize] = 0;

 out:
    if (ws) {
        pgp_status_t pgp_status = pgp_writer_stack_finalize (&err, ws);
        ws = NULL;
        if (pgp_status != 0)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Flushing writer");
    }

    if (signer)
        pgp_tpk_free(signer);

    T("(%s)-> %s", fpr, pep_status_to_string(status));
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
    pgp_tpk_t signer = NULL;
    pgp_writer_stack_t ws = NULL;

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
        status = tpk_find_by_fpr_hex(session, keylist->value, true, &signer, NULL);
        ERROR_OUT(NULL, status, "Looking up key for signing '%s'", keylist->value);
    }

    pgp_writer_t writer = pgp_writer_alloc((void **) ctext, csize);
    writer = pgp_armor_writer_new(&err, writer,
                                  PGP_ARMOR_KIND_MESSAGE, NULL, 0);
    if (!writer)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up armor writer");

    ws = pgp_writer_stack_message(writer);
    ws = pgp_encryptor_new (&err, ws,
                           NULL, 0, keys, keys_count,
                           PGP_ENCRYPTION_MODE_FOR_TRANSPORT);
    if (!ws) {
        pgp_writer_free(writer);
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Setting up encryptor");
    }

    if (sign) {
        pgp_key_t primary_key = pgp_tpk_primary (signer);
        pgp_key_pair_t primary_keypair
            = pgp_key_into_key_pair (NULL, pgp_key_clone (primary_key));
        pgp_key_free (primary_key);
        assert (primary_keypair);
        pgp_signer_t primary_signer = pgp_key_pair_as_signer (primary_keypair);

        ws = pgp_signer_new(&err, ws, &signer, 1);
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

    // Add a terminating NUL for naive users
    void *t = realloc(*ctext, *csize + 1);
    if (! t)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "out of memory");
    *ctext = t;
    (*ctext)[*csize] = 0;

 out:
    if (ws) {
        pgp_status_t pgp_status = pgp_writer_stack_finalize (&err, ws);
        ws = NULL;
        if (pgp_status != 0)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Flushing writer");
    }

    if (signer)
        pgp_tpk_free(signer);
    for (int i = 0; i < keys_count; i ++)
        pgp_tpk_free(keys[i]);
    free(keys);

    T("-> %s", pep_status_to_string(status));
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
    char *userid = NULL;
    pgp_tpk_t tpk = NULL;
    pgp_fingerprint_t pgp_fpr = NULL;
    char *fpr = NULL;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL || identity->fpr[0] == 0);
    assert(identity->username);

    asprintf(&userid, "%s <%s>", identity->username, identity->address);
    if (! userid)
        ERROR_OUT(NULL, PEP_OUT_OF_MEMORY, "asprintf");

    T("(%s)", userid);

    // Generate a key.
    pgp_tsk_t tsk;
    pgp_signature_t rev;
    if (pgp_tsk_new(&err, userid, &tsk, &rev) != 0)
        ERROR_OUT(err, PEP_CANNOT_CREATE_KEY, "Generating a key pair");

    // XXX: We should return this.
    // pgp_signature_free(rev);

    tpk = pgp_tsk_into_tpk(tsk);

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
    if (pgp_fpr)
        pgp_fingerprint_free(pgp_fpr);
    free(fpr);
    if (tpk)
        pgp_tpk_free(tpk);
    free(userid);

    T("-> %s", pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr_raw)
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *fpr = pgp_fingerprint_canonicalize(fpr_raw);

    T("(%s)", fpr);

    // XXX: Can also be used for deleting public keys!!!
    assert(!"implement me");

    T("(%s) -> %s", fpr, pep_status_to_string(status));

    free(fpr);
    return status;
}

// XXX: This needs to handle not only TPKs, but also keyrings and
// revocation certificates.  Right now, we only import a single TPK
// and ignore everything else.
PEP_STATUS pgp_import_keydata(PEP_SESSION session, const char *key_data,
                              size_t size, identity_list **private_idents)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err;

    if (private_idents)
        *private_idents = NULL;

    T("parsing %zd bytes", size);

    pgp_packet_parser_result_t ppr
        = pgp_packet_parser_from_bytes(&err, (uint8_t *) key_data, size);
    if (! ppr)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "Creating packet parser");

    pgp_tag_t tag = pgp_packet_parser_result_tag(ppr);
    switch (tag) {
    case PGP_TAG_SIGNATURE:
        // XXX: Implement me.
        assert(!"Have possible revocation certificate!");
        break;

    case PGP_TAG_PUBLIC_KEY:
    case PGP_TAG_SECRET_KEY: {
        pgp_tpk_t tpk = pgp_tpk_from_packet_parser(&err, ppr);
        if (! tpk)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "parsing key data");

        // If private_idents is not NULL and there is any private key
        // material, it will be saved.
        status = tpk_save(session, tpk, private_idents);
        if (status == PEP_STATUS_OK)
            status = PEP_KEY_IMPORTED;
        ERROR_OUT(NULL, status, "saving TPK");
        break;
    }
    default:
        ERROR_OUT(NULL, PEP_NO_KEY_IMPORTED,
                  "Can't import %s", pgp_tag_to_string(tag));
        break;
    }

 out:
    T("-> %s", pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_export_keydata(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size,
        bool secret)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t secret_key = NULL;
    pgp_tpk_t tpk = NULL;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(*key_data == NULL);
    assert(size);

    *size = 0;

    T("(%s, %s)", fpr, secret ? "secret" : "public");

    if (secret) {
        status = tpk_find_by_fpr_hex(session, fpr, true, &secret_key, NULL);
        if (status == PEP_KEY_NOT_FOUND)
            status = PEP_STATUS_OK;
        ERROR_OUT(NULL, status, "Looking up TSK for %s", fpr);
    }

    pgp_fingerprint_t pgp_fpr = pgp_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, pgp_fpr, false, &tpk, NULL);
    pgp_fingerprint_free(pgp_fpr);
    ERROR_OUT(NULL, status, "Looking up TPK for %s", fpr);

    if (secret_key) {
        tpk = pgp_tpk_merge(&err, tpk, secret_key);
        // pgp_tpk_merge can return NULL if the primary keys don't
        // match.  But, we looked up the tpk by the secret key's
        // fingerprint so this should not be possible.
        assert(tpk);
        if (! tpk)
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "merging TPKs");
        secret_key = NULL;
    }

    pgp_writer_t memory_writer = pgp_writer_alloc((void **) key_data, size);
    if (! memory_writer)
        ERROR_OUT(NULL, PEP_UNKNOWN_ERROR, "creating memory writer");
    pgp_writer_t armor_writer = pgp_armor_writer_new(&err,
                                                     memory_writer,
                                                     PGP_ARMOR_KIND_PUBLICKEY,
                                                     NULL, 0);
    if (! armor_writer) {
        pgp_writer_free(memory_writer);
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "creating armored writer");
    }

    if (secret) {
        pgp_tsk_t tsk = pgp_tpk_into_tsk(tpk);
        if (pgp_tsk_serialize(&err, tsk, armor_writer))
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "serializing TSK");
        tpk = pgp_tsk_into_tpk(tsk);
    } else {
        if (pgp_tpk_serialize(&err, tpk, armor_writer))
            ERROR_OUT(err, PEP_UNKNOWN_ERROR, "serializing TPK");
    }

 out:
    if (tpk)
        pgp_tpk_free(tpk);

    if (armor_writer)
        pgp_writer_free(armor_writer);

    if (secret_key)
        pgp_tpk_free(secret_key);

    T("(%s) -> %s", fpr, pep_status_to_string(status));
    return status;
}

char* _undot_address(const char* address) {
    if (!address)
        return NULL;

    int addr_len = strlen(address);
    const char* at = strstr(address, "@");

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
        // Fingerprint.
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
    if (tpk)
        pgp_tpk_free(tpk);
    if (fpr)
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
    T("(%s) -> %s (%d keys)", pattern, pep_status_to_string(status), len);
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

    if (pgp_tpk_expired(tpk)) {
        *comm_type = PEP_ct_key_expired;
        goto out;
    }

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

        if (pgp_revocation_status_variant(rev) == PGP_REVOCATION_STATUS_REVOKED)
            continue;

        if (! pgp_signature_key_alive(sig, key))
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
    if (tpk)
        pgp_tpk_free(tpk);

    T("(%s) -> %s", fpr, pep_comm_type_to_string(*comm_type));
    return status;
}


PEP_STATUS pgp_renew_key(
    PEP_SESSION session, const char *fpr, const timestamp *ts)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t tpk = NULL;
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
    tpk = pgp_tpk_set_expiry(&err, tpk, delta);
    if (! tpk)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "setting expiration");

    status = tpk_save(session, tpk, NULL);
    tpk = NULL;
    ERROR_OUT(NULL, status, "Saving %s", fpr);

 out:
    if (tpk)
        pgp_tpk_free(tpk);

    T("(%s) -> %s", fpr, pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_revoke_key(
    PEP_SESSION session, const char *fpr, const char *reason)
{
    PEP_STATUS status = PEP_STATUS_OK;
    pgp_error_t err = NULL;
    pgp_tpk_t tpk = NULL;

    T("(%s)", fpr);

    status = tpk_find_by_fpr_hex(session, fpr, true, &tpk, NULL);
    ERROR_OUT(NULL, status, "Looking up %s", fpr);

    pgp_key_t primary_key = pgp_tpk_primary (tpk);
    pgp_key_pair_t primary_keypair
        = pgp_key_into_key_pair (NULL, pgp_key_clone (primary_key));
    pgp_key_free (primary_key);
    assert (primary_keypair);
    pgp_signer_t primary_signer = pgp_key_pair_as_signer (primary_keypair);

    tpk = pgp_tpk_revoke_in_place(&err, tpk, primary_signer,
                                  PGP_REASON_FOR_REVOCATION_UNSPECIFIED,
                                  reason);
    pgp_signer_free (primary_signer);
    pgp_key_pair_free (primary_keypair);
    if (! tpk)
        ERROR_OUT(err, PEP_UNKNOWN_ERROR, "setting expiration");

    assert(pgp_revocation_status_variant(pgp_tpk_revocation_status(tpk))
           == PGP_REVOCATION_STATUS_REVOKED);

    status = tpk_save(session, tpk, NULL);
    tpk = NULL;
    ERROR_OUT(NULL, status, "Saving %s", fpr);

 out:
    if (tpk)
        pgp_tpk_free(tpk);

    T("(%s) -> %s", fpr, pep_status_to_string(status));
    return status;
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

    // Is the TPK live?
    *expired = !pgp_tpk_alive_at(tpk, when);
    if (*expired)
        goto out;

    // Are there at least one certification subkey, one signing subkey
    // and one encryption subkey that are live?
    int can_certify = 0, can_encrypt = 0, can_sign = 0;

    pgp_tpk_key_iter_t key_iter = pgp_tpk_key_iter_valid(tpk);
    pgp_key_t key;
    pgp_signature_t sig;
    pgp_revocation_status_t rev;
    while ((key = pgp_tpk_key_iter_next(key_iter, &sig, &rev))) {
        if (! sig)
            continue;

        if (pgp_revocation_status_variant(rev) == PGP_REVOCATION_STATUS_REVOKED)
            continue;

        if (!pgp_signature_key_alive_at(sig, key, when))
            continue;

        if (pgp_signature_can_encrypt_for_transport(sig)
            || pgp_signature_can_encrypt_at_rest(sig))
            can_encrypt = 1;
        if (pgp_signature_can_sign(sig))
            can_sign = 1;
        if (pgp_signature_can_certify(sig))
            can_certify = 1;

        if (can_encrypt && can_sign && can_certify)
            break;
    }
    pgp_tpk_key_iter_free(key_iter);

    *expired = !(can_encrypt && can_sign && can_certify);

 out:
    if (tpk)
        pgp_tpk_free(tpk);
    T("(%s) -> %s", fpr, pep_status_to_string(status));
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
    T("(%s) -> %s", fpr, pep_status_to_string(status));
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
    T("(%s) -> %s", fpr, pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_binary(const char **path)
{
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
      fpr, *has_private ? "priv" : "pub", pep_status_to_string(status));
    return status;
}
