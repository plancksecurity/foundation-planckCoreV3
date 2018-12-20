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

// Set to 0 to disable tracing.
#if 1
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
#  define DUMP_ERR(__de_session, __de_status, ...) do {             \
    TC(__VA_ARGS__);                                                \
    _T(": ");                                                       \
    if ((__de_session->ctx)) {                                      \
        sq_error_t __de_err                                         \
            = sq_context_last_error((__de_session->ctx));           \
        if (__de_err)                                               \
            _T("Sequoia: %s => ", sq_error_string(__de_err));       \
        sq_error_free(__de_err);                                    \
    }                                                               \
    _T("%s\n", pep_status_to_string(__de_status));                  \
} while(0)

// If __ec_status is an error, then disable the error, set 'status' to
// it, and jump to 'out'.
#define ERROR_OUT(__e_session, __ec_status, ...) do {               \
    PEP_STATUS ___ec_status = (__ec_status);                        \
    if ((___ec_status) != PEP_STATUS_OK) {                          \
        DUMP_ERR((__e_session), (___ec_status), ##__VA_ARGS__);     \
        status = (___ec_status);                                    \
        goto out;                                                   \
    }                                                               \
} while(0)

PEP_STATUS pgp_init(PEP_SESSION session, bool in_first)
{
    PEP_STATUS status = PEP_STATUS_OK;

    sq_error_t err;
    session->ctx = sq_context_new("foundation.pep", &err);
    if (session->ctx == NULL)
        ERROR_OUT(session, PEP_INIT_GPGME_INIT_FAILED,
                  "initializing sequoia context");

    session->store = sq_store_open(session->ctx, "foundation.pep");
    if (session->store == NULL)
        ERROR_OUT(session, PEP_INIT_GPGME_INIT_FAILED, "opening the store");


    // Create the home directory.
    char *home_env = getenv("HOME");
    if (!home_env)
        ERROR_OUT(session, PEP_INIT_GPGME_INIT_FAILED, "HOME unset");

    // Create the DB and initialize it.
    char *path = NULL;
    asprintf(&path, "%s/.pEp_keys.db", home_env);
    if (!path)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");

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
        ERROR_OUT(session, PEP_INIT_CANNOT_OPEN_DB,
                  "opening keys DB: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_exec(session->key_db,
                                 "PRAGMA locking_mode=NORMAL;\n"
                                 "PRAGMA journal_mode=WAL;\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(session, PEP_INIT_CANNOT_OPEN_DB,
                  "setting pragmas: %s", sqlite3_errmsg(session->key_db));

    sqlite3_busy_timeout(session->key_db, BUSY_WAIT_TIME);

    sqlite_result = sqlite3_exec(session->key_db,
                                 "CREATE TABLE IF NOT EXISTS keys (\n"
                                 "   primary_key TEXT PRIMARY KEY,\n"
                                 "   tsk BLOB\n"
                                 ");\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(session, PEP_INIT_CANNOT_OPEN_DB,
                  "creating keys table: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result = sqlite3_exec(session->key_db,
                                 "CREATE TABLE IF NOT EXISTS subkeys (\n"
                                 "   subkey TEXT PRIMARY KEY,\n"
                                 "   primary_key TEXT,\n"
                                 "   FOREIGN KEY (primary_key)\n"
                                 "       REFERENCES keys(primary_key)\n"
                                 "     ON DELETE CASCADE\n"
                                 ");\n",
                                 NULL, NULL, NULL);
    if (sqlite_result != SQLITE_OK)
        ERROR_OUT(session, PEP_INIT_CANNOT_OPEN_DB,
                  "creating subkeys table: %s",
                  sqlite3_errmsg(session->key_db));

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "begin transaction",
                             -1, &session->begin_transaction, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "commit transaction",
                             -1, &session->commit_transaction, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "rollback transaction",
                             -1, &session->rollback_transaction, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "INSERT OR REPLACE INTO keys"
                             "   (primary_key, tsk)"
                             " VALUES (?, ?)",
                             -1, &session->tsk_save_insert_primary, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "INSERT OR REPLACE INTO subkeys"
                             "   (subkey, primary_key)"
                             " VALUES (?, ?)",
                             -1, &session->tsk_save_insert_subkeys, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db, "select tsk from keys",
                             -1, &session->tsk_all, NULL);
    assert(sqlite_result == SQLITE_OK);

    sqlite_result
        = sqlite3_prepare_v2(session->key_db,
                             "SELECT keys.tsk FROM subkeys"
                             " LEFT JOIN keys"
                             "  ON subkeys.primary_key"
                             "     == keys.primary_key"
                             " WHERE subkey == ?",
                             -1, &session->tsk_find_by_keyid, NULL);
    assert(sqlite_result == SQLITE_OK);

 out:
    if (status != PEP_STATUS_OK)
        pgp_release(session, in_first);
    return status;
}

void pgp_release(PEP_SESSION session, bool out_last)
{
    if (session->begin_transaction)
        sqlite3_finalize(session->begin_transaction);
    session->begin_transaction = NULL;
    if (session->commit_transaction)
        sqlite3_finalize(session->commit_transaction);
    session->commit_transaction = NULL;
    if (session->rollback_transaction)
        sqlite3_finalize(session->rollback_transaction);
    session->rollback_transaction = NULL;
    if (session->tsk_save_insert_primary)
        sqlite3_finalize(session->tsk_save_insert_primary);
    session->tsk_save_insert_primary = NULL;
    if (session->tsk_save_insert_subkeys)
        sqlite3_finalize(session->tsk_save_insert_subkeys);
    session->tsk_save_insert_subkeys = NULL;
    if (session->tsk_all)
        sqlite3_finalize(session->tsk_all);
    session->tsk_all = NULL;
    if (session->tsk_find_by_keyid)
        sqlite3_finalize(session->tsk_find_by_keyid);
    session->tsk_find_by_keyid = NULL;

    if (session->key_db) {
        int result = sqlite3_close_v2(session->key_db);
        if (result != 0)
            DUMP_ERR(session, PEP_UNKNOWN_ERROR,
                     "Closing key DB: sqlite3_close_v2: %s",
                     sqlite3_errstr(result));
        session->key_db = NULL;
    }

    if (session->store) {
        sq_store_free(session->store);
        session->store = NULL;
    }

    if (session->ctx) {
        sq_context_free(session->ctx);
        session->ctx = NULL;
    }
}

// Ensures that a fingerprint is in canonical form.  A canonical
// fingerprint doesn't contain any white space.
//
// This function does *not* consume fpr.
static char *sq_fingerprint_canonicalize(const char *) __attribute__((nonnull));
static char *sq_fingerprint_canonicalize(const char *fpr)
{
    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    char *fpr_canonicalized = sq_fingerprint_to_hex(sq_fpr);
    sq_fingerprint_free(sq_fpr);

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


// Returns the TSK identified by the provided keyid.
//
// If tsk is NULL, the TSK is not parsed and this function simply
// returns whether the key is locally available.
static PEP_STATUS tsk_find_by_keyid_hex(PEP_SESSION, const char *, sq_tsk_t *)
  __attribute__((nonnull(1, 2)));
static PEP_STATUS tsk_find_by_keyid_hex(
        PEP_SESSION session,
        const char *keyid_hex,
        sq_tsk_t *tsk)
{
    PEP_STATUS status = PEP_STATUS_OK;
    T("%s", keyid_hex);

    sqlite3_stmt *stmt = session->tsk_find_by_keyid;
    sqlite3_bind_text(stmt, 1, keyid_hex, -1, SQLITE_STATIC);
    int sqlite_result = sqlite3_step(stmt);
    switch (sqlite_result) {
    case SQLITE_ROW:
        if (tsk) {
            // Get the TSK from the first column.
            int data_len = sqlite3_column_bytes(stmt, 0);
            const void *data = sqlite3_column_blob(stmt, 0);

            sq_tpk_t tpk = sq_tpk_from_bytes(session->ctx, data, data_len);
            if (!tpk)
                ERROR_OUT(session, PEP_GET_KEY_FAILED, "parsing TPK");

            *tsk = sq_tpk_into_tsk(tpk);
        }
        break;
    case SQLITE_DONE:
        // Got nothing.
        status = PEP_KEY_NOT_FOUND;
        break;
    default:
        ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                  "stepping tsk_find_by_keyid: %s",
                  sqlite3_errmsg(session->key_db));
    }

 out:
    sqlite3_reset(stmt);
    T("%s -> %s", keyid_hex, pep_status_to_string(status));
    return status;
}

// See tsk_find_by_keyid_hex.
PEP_STATUS tsk_find_by_keyid(PEP_SESSION, sq_keyid_t, sq_tsk_t *)
    __attribute__((nonnull(1, 2)));
PEP_STATUS tsk_find_by_keyid(
        PEP_SESSION session, sq_keyid_t keyid, sq_tsk_t *tsk)
{
    char *keyid_hex = sq_keyid_to_hex(keyid);
    if (! keyid_hex)
        return PEP_OUT_OF_MEMORY;
    PEP_STATUS status = tsk_find_by_keyid_hex(session, keyid_hex, tsk);
    free(keyid_hex);
    return status;
}

// See tsk_find_by_keyid_hex.
static PEP_STATUS tsk_find_by_fpr(PEP_SESSION, sq_fingerprint_t, sq_tsk_t *)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS tsk_find_by_fpr(
        PEP_SESSION session, sq_fingerprint_t fpr, sq_tsk_t *tsk)
{
    sq_keyid_t keyid = sq_fingerprint_to_keyid(fpr);
    if (! keyid)
        return PEP_OUT_OF_MEMORY;
    PEP_STATUS status = tsk_find_by_keyid(session, keyid, tsk);
    sq_keyid_free(keyid);
    return status;
}

// See tsk_find_by_keyid_hex.
static PEP_STATUS tsk_find_by_fpr_hex(PEP_SESSION, const char *, sq_tsk_t *)
    __attribute__((nonnull(1, 2)));
static PEP_STATUS tsk_find_by_fpr_hex(
        PEP_SESSION session, const char *fpr, sq_tsk_t *tsk)
{
    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    if (! sq_fpr)
        return PEP_OUT_OF_MEMORY;
    PEP_STATUS status = tsk_find_by_fpr(session, sq_fpr, tsk);
    sq_fingerprint_free(sq_fpr);
    return status;
}


// Saves the specified TSK.
//
// This function takes ownership of TSK.
static PEP_STATUS tsk_save(PEP_SESSION, sq_tsk_t) __attribute__((nonnull));
static PEP_STATUS tsk_save(PEP_SESSION session, sq_tsk_t tsk)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_fingerprint_t sq_fpr = NULL;
    char *fpr = NULL;
    void *tsk_buffer = NULL;
    size_t tsk_buffer_len = 0;
    int tried_commit = 0;
    sq_tpk_t tpk = sq_tsk_tpk(tsk); /* Reference. */
    sq_tpk_key_iter_t key_iter = NULL;

    sq_fpr = sq_tpk_fingerprint(tpk);
    fpr = sq_fingerprint_to_hex(sq_fpr);
    T("%s", fpr);

    // Merge any existing data into TSK.
    sq_tsk_t current = NULL;
    status = tsk_find_by_fpr(session, sq_fpr, &current);
    if (status == PEP_KEY_NOT_FOUND)
        status = PEP_STATUS_OK;
    else
        ERROR_OUT(session, status, "Looking up %s", fpr);
    if (current) {
        tpk = sq_tpk_merge(session->ctx,
                           sq_tsk_into_tpk(tsk), sq_tsk_into_tpk(current));
        tsk = sq_tpk_into_tsk(tpk);
        tpk = sq_tsk_tpk(tsk);
    }


    // Serialize it.
    sq_writer_t writer = sq_writer_alloc(&tsk_buffer, &tsk_buffer_len);
    if (! writer)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");

    sq_status_t sq_status = sq_tsk_serialize(session->ctx, tsk, writer);
    //sq_writer_free(writer);
    if (sq_status != 0)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Serializing TSK");


    // Insert the TSK into the DB.
    sqlite3_stmt *stmt = session->begin_transaction;
    int sqlite_result = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (sqlite_result != SQLITE_DONE)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                  "begin transaction failed: %s",
                  sqlite3_errmsg(session->key_db));

    stmt = session->tsk_save_insert_primary;
    sqlite3_bind_text(stmt, 1, fpr, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, tsk_buffer, tsk_buffer_len, SQLITE_STATIC);

    sqlite_result = sqlite3_step(stmt);
    sqlite3_reset(stmt);
    if (sqlite_result != SQLITE_DONE)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                  "Saving TSK to DB: %s",
                  sqlite3_errmsg(session->key_db));

    // Insert the "subkeys" (the primary key and the subkeys).
    stmt = session->tsk_save_insert_subkeys;
    key_iter = sq_tpk_key_iter(tpk);
    sq_p_key_t key;
    while ((key = sq_tpk_key_iter_next(key_iter, NULL, NULL))) {
        sq_keyid_t keyid = sq_p_key_keyid(key);
        char *keyid_hex = sq_keyid_to_hex(keyid);
        T("  subkey: %s", keyid_hex);
        sqlite3_bind_text(stmt, 1, keyid_hex, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, fpr, -1, SQLITE_STATIC);

        sqlite_result = sqlite3_step(stmt);
        sqlite3_reset(stmt);
        free(keyid_hex);
        sq_keyid_free(keyid);
        if (sqlite_result != SQLITE_DONE) {
            sq_tpk_key_iter_free(key_iter);
            ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                      "Updating subkeys: %s", sqlite3_errmsg(session->key_db));
        }
    }
    sq_tpk_key_iter_free(key_iter);
    key_iter = NULL;

 out:
    // Prevent ERROR_OUT from causing an infinite loop.
    if (! tried_commit) {
        tried_commit = 1;
        stmt = status == PEP_STATUS_OK
            ? session->commit_transaction : session->rollback_transaction;
        int sqlite_result = sqlite3_step(stmt);
        sqlite3_reset(stmt);
        if (sqlite_result != SQLITE_DONE)
            ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                      status == PEP_STATUS_OK
                      ? "commit failed: %s" : "rollback failed: %s",
                      sqlite3_errmsg(session->key_db));
    }

    T("(%s) -> %s", fpr, pep_status_to_string(status));

    if (key_iter)
        sq_tpk_key_iter_free(key_iter);
    if (stmt)
      sqlite3_reset(stmt);
    free(tsk_buffer);
    sq_tsk_free(tsk);
    free(fpr);
    sq_fingerprint_free(sq_fpr);

    return status;
}

// Returns all known TSKs.
static PEP_STATUS tsk_all(PEP_SESSION, sq_tsk_t **, int *) __attribute__((nonnull));
static PEP_STATUS tsk_all(PEP_SESSION session, sq_tsk_t **tsksp, int *tsks_countp) {
    PEP_STATUS status = PEP_STATUS_OK;

    int tsks_count = 0;
    int tsks_capacity = 8;
    sq_tsk_t *tsks = calloc(tsks_capacity, sizeof(sq_tsk_t));
    if (!tsks)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");

    sqlite3_stmt *stmt = session->tsk_all;
    while (true) {
        switch (sqlite3_step(stmt)) {
        case SQLITE_ROW: {
            int data_len = sqlite3_column_bytes(stmt, 0);
            const void *data = sqlite3_column_blob(stmt, 0);
            sq_tpk_t tpk = sq_tpk_from_bytes(session->ctx, data, data_len);
            if (!tpk) {
                ERROR_OUT(session, PEP_GET_KEY_FAILED, "parsing TSK");
            } else {
                if (tsks_count == tsks_capacity) {
                    tsks_capacity *= 2;
                    tsks = realloc(tsks, sizeof(tsks[0]) * tsks_capacity);
                    if (!tsks)
                        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "tsks");
                }
                tsks[tsks_count ++] = sq_tpk_into_tsk(tpk);
            }
            break;
        }
        default:
            ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                      "stepping sqlite statement: %s",
                      sqlite3_errmsg(session->key_db));
        case SQLITE_DONE:
            goto out;
        }
    }

 out:
    sqlite3_reset(stmt);

    if (status != PEP_STATUS_OK) {
        for (int i = 0; i < tsks_count; i ++)
            sq_tsk_free(tsks[i]);
        free(tsks);
    } else {
        *tsksp = tsks;
        *tsks_countp = tsks_count;
    }

    return status;
}

// Returns the key with the label LABEL.
//
// The return is returned in *KEY and must be freed using sq_tpk_free.
//
// Note: we maintain labels for the fingerprint of primary keys, pep
// user ids, and email addresses.  If you want to look something up by
// subkey id, use tpk_find_by_keyid.
static PEP_STATUS tpk_find_by_label(PEP_SESSION, const char *, sq_tpk_t *)
    __attribute__((nonnull));
static PEP_STATUS tpk_find_by_label(PEP_SESSION session, const char *label, sq_tpk_t *tpk)
{
    PEP_STATUS status = PEP_STATUS_OK;

    sq_binding_t binding
        = sq_store_lookup(session->ctx, session->store, label);
    if (!binding)
        ERROR_OUT(session, PEP_KEY_NOT_FOUND, "looking up label %s", label);

    *tpk = sq_binding_tpk(session->ctx, binding);
    if (!*tpk)
        ERROR_OUT(session, PEP_GET_KEY_FAILED, "getting TPK");

 out:
    if (binding)
        sq_binding_free(binding);

    return status;
}

// Returns the key with keyid KEYID.
//
// Note: this function will match both the primary key as well as any
// subkeys.
static PEP_STATUS tpk_find_by_keyid(PEP_SESSION, sq_keyid_t, sq_tpk_t *)
    __attribute__((nonnull));
static PEP_STATUS tpk_find_by_keyid(PEP_SESSION session, sq_keyid_t keyid,
                                    sq_tpk_t *tpk)
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *keyid_hex = sq_keyid_to_hex(keyid);

    sq_key_t key = sq_store_lookup_by_subkeyid(session->ctx, keyid);
    if (!key)
        ERROR_OUT(session, PEP_KEY_NOT_FOUND,
                  "looking up key by keyid %s", keyid_hex);

    *tpk = sq_key_tpk(session->ctx, key);
    if (!*tpk)
        ERROR_OUT(session, PEP_GET_KEY_FAILED, "getting TPK");

 out:
    free(keyid_hex);

    return status;
}

// Returns the key with fingerprint FPR.
//
// Note: this function will match both the primary key as well as any
// subkeys.
static PEP_STATUS tpk_find_by_fpr(PEP_SESSION, sq_fingerprint_t, sq_tpk_t *)
    __attribute__((nonnull));
static PEP_STATUS tpk_find_by_fpr(PEP_SESSION session, sq_fingerprint_t fpr,
                                  sq_tpk_t *tpk)
{
    sq_keyid_t keyid = sq_fingerprint_to_keyid(fpr);
    PEP_STATUS status = tpk_find_by_keyid(session, keyid, tpk);
    sq_keyid_free(keyid);
    return status;
}



// Saves a TPK.
//
// Creates labels under the fingerprint, address (if not NULL), and
// the email address in each user id.
//
// If there are any keys with private key material, saves that
// information in private_idents (if not NULL).
//
// This function takes ownership of the tpk.
static PEP_STATUS tpk_save(PEP_SESSION, sq_tpk_t, const char *,
                           identity_list **, int)
  __attribute__((nonnull(1, 2)));
static PEP_STATUS tpk_save(PEP_SESSION session, sq_tpk_t tpk,
                           const char *address, identity_list **private_idents,
                           int replace_bindings)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_user_id_binding_iter_t iter = NULL;
    sq_user_id_binding_t user_id_binding = NULL;

    if (private_idents)
        *private_idents = NULL;

    sq_fingerprint_t sq_fpr = sq_tpk_fingerprint(tpk);
    char *fpr = sq_fingerprint_to_hex(sq_fpr);
    T("(%s)", fpr);

    // Import the public part in the store.  If it was already present
    // in the store, it will be merged.  We don't work with the merged
    // TPK, because we only care about new user ids.
    sq_tpk_t merged = sq_store_import(session->ctx, session->store, fpr, tpk);
    if (! merged)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Merging TPK (%s)", fpr);
    sq_tpk_free(merged);

    // Add the pep user id label.
    if (address) {
        int first_try = 1;
        sq_binding_t binding;

    make_address_binding:
        binding = sq_store_add(session->ctx, session->store, address, sq_fpr);
        if (! binding) {
            // An error occured.  There's a good chance this is
            // because the binding already exists.
            if (replace_bindings && first_try) {
                T("replacing userid binding %s -> %s", address, fpr);

                // We should replace the existing binding.
                binding = sq_store_lookup(session->ctx, session->store, address);
                if (binding) {
                    if (sq_binding_delete(session->ctx, binding)) {
                        DUMP_ERR(session, PEP_STATUS_OK,
                                 "Delete binding %s", address);
                        sq_binding_free(binding);
                    }

                    first_try = 0;
                    goto make_address_binding;
                }
            }

            // This is a soft error: we always prefer the existing
            // binding.
            DUMP_ERR(session, PEP_STATUS_OK,
                     "Creating userid binding %s -> %s", address, fpr);
        } else {
            sq_binding_free(binding);
        }
    }

    // Create a binding for each user id.
    //
    // Note: the iterator only returns valid user ids in the sense
    // that the user id has a self-signature or a self-revocation
    // certificate.
    int first = 1;
    iter = sq_tpk_user_id_binding_iter(tpk);
    while ((user_id_binding = sq_user_id_binding_iter_next(iter))) {
        char *user_id = sq_user_id_binding_user_id(user_id_binding);
        if (!user_id) {
            // Completely ignore insane user ids (those with interior
            // NUL bytes).
            free(user_id);
            continue;
        }

        // Ignore bindings with a self-revocation certificate, but no
        // self-signature.
        if (!sq_user_id_binding_selfsig(user_id_binding)) {
            free(user_id);
            continue;
        }

        char *name, *email;
        user_id_split(user_id, &name, &email); /* user_id is comsumed.  */

        if (email) {
            int first_try = 1;
            sq_binding_t binding;

        make_email_binding:
            binding = sq_store_add(session->ctx, session->store, email, sq_fpr);
            if (! binding) {
                // An error occured.  There's a good chance this is
                // because the binding already exists.
                if (replace_bindings && first_try) {
                    // We should replace the existing binding.
                    binding = sq_store_lookup(session->ctx, session->store, email);
                    if (binding) {
                        if (sq_binding_delete(session->ctx, binding)) {
                            DUMP_ERR(session, PEP_STATUS_OK,
                                     "Delete binding %s", email);
                            sq_binding_free(binding);
                        }

                        first_try = 0;
                        goto make_email_binding;
                    }
                }

                // This is a soft error: we always prefer the existing
                // binding.
                DUMP_ERR(session, PEP_UNKNOWN_ERROR,
                         "Creating email binding: %s -> %s", email, fpr);
            } else {
                sq_binding_free(binding);
            }

            if (first && private_idents && sq_tpk_is_tsk(tpk)) {
                first = 0;

                // Create an identity for the primary user id.
                pEp_identity *ident = new_identity(email, fpr, NULL, name);
                if (ident == NULL)
                    ERROR_OUT(session, PEP_OUT_OF_MEMORY, "new_identity");

                *private_idents = identity_list_add(*private_idents, ident);
                if (*private_idents == NULL)
                    ERROR_OUT(session, PEP_OUT_OF_MEMORY, "identity_list_add");
            }
        }
    }

    sq_user_id_binding_iter_free(iter);
    iter = NULL;

    // If it has any private key material, save it in the TSK store.
    if (sq_tpk_is_tsk(tpk)) {
        status = tsk_save(session, sq_tpk_into_tsk(tpk));
        tpk = NULL;
        ERROR_OUT(session, status, "Saving TSK");
    }

 out:
    T("(%s) -> %s", fpr, pep_status_to_string(status));

    if (iter)
        sq_user_id_binding_iter_free(iter);
    free(fpr);
    if (sq_fpr)
        sq_fingerprint_free(sq_fpr);
    if (tpk)
        sq_tpk_free(tpk);

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

static sq_status_t
get_public_keys_cb(void *cookie_raw,
                   sq_keyid_t *keyids, size_t keyids_len,
                   sq_tpk_t **tpks, size_t *tpk_len,
                   void (**our_free)(void *))
{
    struct decrypt_cookie *cookie = cookie_raw;
    PEP_SESSION session = cookie->session;

    *tpks = calloc(keyids_len, sizeof(*tpks));
    if (!*tpks)
        return SQ_STATUS_UNKNOWN_ERROR;
    *our_free = free;

    int i, j;
    j = 0;
    for (i = 0; i < keyids_len; i ++) {
        sq_tpk_t tpk = NULL;
        sq_status_t status = tpk_find_by_keyid(session, keyids[i], &tpk);
        if (status == SQ_STATUS_SUCCESS)
            (*tpks)[j ++] = tpk;
    }
    *tpk_len = j;
    return SQ_STATUS_SUCCESS;
}

static sq_status_t
get_secret_keys_cb(void *cookie_opaque,
                   sq_pkesk_t *pkesks, size_t pkesk_count,
                   sq_skesk_t *skesks, size_t skesk_count,
                   sq_secret_t *secret)
{
    struct decrypt_cookie *cookie = cookie_opaque;
    PEP_SESSION session = cookie->session;
    sq_tsk_t *tsks = NULL;
    int tsks_count = 0;
    int wildcards = 0;

    if (cookie->get_secret_keys_called)
        // Prevent iterations, which isn't needed since we don't
        // support SKESKs.
        return SQ_STATUS_UNKNOWN_ERROR;
    cookie->get_secret_keys_called = 1;

    T("%zd PKESKs", pkesk_count);

    for (int i = 0; i < pkesk_count; i ++) {
        sq_pkesk_t pkesk = pkesks[i];
        sq_keyid_t keyid = sq_pkesk_recipient(pkesk); /* Reference. */
        char *keyid_str = sq_keyid_to_hex(keyid);
        sq_tpk_key_iter_t key_iter = NULL;

        T("Considering PKESK for %s", keyid_str);

        if (strcmp(keyid_str, "0000000000000000") == 0) {
            // Initially ignore wildcards.
            wildcards = 1;
            goto eol;
        }

        // Collect the recipients.  Note: we must return the primary
        // key's fingerprint.
        sq_tpk_t tpk = NULL;
        if (tpk_find_by_keyid(session, keyid, &tpk) == PEP_STATUS_OK) {
            sq_fingerprint_t fp = sq_tpk_fingerprint(tpk);
            char *fp_string = sq_fingerprint_to_hex(fp);
            stringlist_add_unique(cookie->recipient_keylist, fp_string);
            free(fp_string);
            sq_fingerprint_free(fp);
            sq_tpk_free(tpk);
        }

        if (cookie->decrypted)
            goto eol;

        // See if we have the secret key.
        sq_tsk_t tsk = NULL;
        PEP_STATUS s = tsk_find_by_keyid(cookie->session, keyid, &tsk);
        if (s != PEP_STATUS_OK) {
            if (s != PEP_KEY_NOT_FOUND)
                DUMP_ERR(cookie->session, s, "Parsing key %s", keyid_str);
            else
                T("No secret key material for %s", keyid_str);
            goto eol;
        }

        tpk = sq_tsk_tpk(tsk);
        key_iter = sq_tpk_key_iter(tpk);
        sq_p_key_t key;
        while ((key = sq_tpk_key_iter_next(key_iter, NULL, NULL))) {
            sq_keyid_t this_keyid = sq_p_key_keyid(key);
            char *this_keyid_hex = sq_keyid_to_hex(this_keyid);
            sq_keyid_free(this_keyid);

            int match = strcmp(keyid_str, this_keyid_hex) == 0;
            free(this_keyid_hex);
            if (match)
                break;
        }

        if (key == NULL)
            assert(!"Inconsistent DB: key doesn't contain a subkey with keyid!");

        uint8_t algo;
        uint8_t session_key[1024];
        size_t session_key_len = sizeof(session_key);
        if (sq_pkesk_decrypt(cookie->session->ctx,
                             pkesk, key, &algo,
                             session_key, &session_key_len) != 0) {
            DUMP_ERR(session, PEP_UNKNOWN_ERROR, "sq_pkesk_decrypt");
            goto eol;
        }

        T("Decrypted PKESK for %s", keyid_str);

        *secret = sq_secret_cached(algo, session_key, session_key_len);
        cookie->decrypted = 1;

    eol:
        free(keyid_str);
        if (key_iter)
            sq_tpk_key_iter_free(key_iter);
    }

    // Consider wildcard recipients.
    if (wildcards) for (int i = 0; i < pkesk_count && !cookie->decrypted; i ++) {
        sq_pkesk_t pkesk = pkesks[i];
        sq_keyid_t keyid = sq_pkesk_recipient(pkesk); /* Reference. */
        char *keyid_str = sq_keyid_to_hex(keyid);
        sq_tpk_key_iter_t key_iter = NULL;

        if (strcmp(keyid_str, "0000000000000000") != 0)
            goto eol2;

        if (!tsks) {
            if (tsk_all(session, &tsks, &tsks_count) != PEP_STATUS_OK) {
                DUMP_ERR(session, PEP_UNKNOWN_ERROR, "Getting all tsks");
            }
        }

        for (int j = 0; j < tsks_count; j ++) {
            sq_tpk_t tpk = sq_tsk_tpk(tsks[j]);

            key_iter = sq_tpk_key_iter(tpk);
            sq_p_key_t key;
            sq_signature_t selfsig;
            while ((key = sq_tpk_key_iter_next(key_iter, &selfsig, NULL))) {
                if (! (sq_signature_can_encrypt_at_rest(selfsig)
                       || sq_signature_can_encrypt_for_transport(selfsig)))
                    continue;

                // Note: for decryption to appear to succeed, we must
                // get a valid algorithm (8 of 256 values) and a
                // 16-bit checksum must match.  Thus, we have about a
                // 1 in 2**21 chance of having a false positive here.
                uint8_t algo;
                uint8_t session_key[1024];
                size_t session_key_len = sizeof(session_key);
                if (sq_pkesk_decrypt(cookie->session->ctx, pkesk, key,
                                     &algo, session_key, &session_key_len))
                    continue;

                // Add it to the recipient list.
                sq_fingerprint_t fp = sq_tpk_fingerprint(tpk);
                char *fp_string = sq_fingerprint_to_hex(fp);
                T("wildcard recipient appears to be %s", fp_string);
                stringlist_add_unique(cookie->recipient_keylist, fp_string);
                free(fp_string);
                sq_fingerprint_free(fp);

                *secret = sq_secret_cached(algo, session_key, session_key_len);
                cookie->decrypted = 1;
            }

            sq_tpk_key_iter_free(key_iter);
            key_iter = NULL;
        }
    eol2:
        free(keyid_str);
        if (key_iter)
            sq_tpk_key_iter_free(key_iter);
    }

    if (tsks) {
        for (int i = 0; i < tsks_count; i ++)
            sq_tsk_free(tsks[i]);
        free(tsks);
    }

    return cookie->decrypted ? SQ_STATUS_SUCCESS : SQ_STATUS_UNKNOWN_ERROR;
}

static sq_status_t
check_signatures_cb(void *cookie_opaque,
                   sq_verification_results_t results, size_t levels)
{
    struct decrypt_cookie *cookie = cookie_opaque;
    PEP_SESSION session = cookie->session;

    int level;
    for (level = 0; level < levels; level ++) {
        sq_verification_result_t *vrs;
        size_t vr_count;
        sq_verification_results_at_level(results, level, &vrs, &vr_count);

        int i;
        for (i = 0; i < vr_count; i ++) {
            sq_tpk_t tpk = NULL;
            sq_verification_result_code_t code
                = sq_verification_result_code(vrs[i]);

            if (code == SQ_VERIFICATION_RESULT_CODE_BAD_CHECKSUM) {
                cookie->bad_checksums ++;
                continue;
            }
            if (code == SQ_VERIFICATION_RESULT_CODE_MISSING_KEY) {
                // No key, nothing we can do.
                cookie->missing_keys ++;
                continue;
            }

            // We need to add the fingerprint of the primary key to
            // cookie->signer_keylist.
            sq_signature_t sig = sq_verification_result_signature(vrs[i]);

            // First try looking up by the TPK using the
            // IssuerFingerprint subpacket.
            sq_fingerprint_t issuer_fp = sq_signature_issuer_fingerprint(sig);
            if (issuer_fp) {
                sq_keyid_t issuer = sq_fingerprint_to_keyid(issuer_fp);
                if (tpk_find_by_keyid(session, issuer, &tpk) != PEP_STATUS_OK)
                    ; // Soft error.  Ignore.
                sq_keyid_free(issuer);
                sq_fingerprint_free(issuer_fp);
            }

            // If that is not available, try using the Issuer subpacket.
            if (!tpk) {
                sq_keyid_t issuer = sq_signature_issuer(sig);
                if (issuer) {
                    if (tpk_find_by_keyid(session, issuer, &tpk) != PEP_STATUS_OK)
                        ; // Soft error.  Ignore.
                }
                sq_keyid_free(issuer);
            }

            if (tpk) {
                // Ok, we have a TPK.
                sq_fingerprint_t fp = sq_tpk_fingerprint(tpk);
                char *fp_str = sq_fingerprint_to_hex(fp);
                stringlist_add_unique(cookie->signer_keylist, fp_str);

                // XXX: Check that the TPK and the key used to make
                // the signature and the signature itself are alive
                // and not revoked.  Revoked =>
                // PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH; Expired key
                // or sig => PEP_DECRYPTED.
                cookie->good_checksums ++;

                free(fp_str);
                sq_fingerprint_free(fp);
                sq_tpk_free(tpk);
            } else {
                // If we get
                // SQ_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM, then the
                // TPK should be available.  But, another process
                // could have deleted the key from the store in the
                // mean time, so be tolerant.
                cookie->missing_keys ++;
            }
        }
    }

    return SQ_STATUS_SUCCESS;
}

PEP_STATUS pgp_decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct decrypt_cookie cookie = { session, 0, NULL, NULL, 0, 0, 0, };
    sq_reader_t reader = NULL;
    sq_writer_t writer = NULL;
    *ptext = NULL;
    *psize = 0;

    // XXX: We don't yet handle detached signatures over encrypted
    // messages.
    assert(!dsigtext);

    cookie.recipient_keylist = new_stringlist(NULL);
    if (!cookie.recipient_keylist)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "recipient_keylist");

    cookie.signer_keylist = new_stringlist(NULL);
    if (!cookie.signer_keylist)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "signer_keylist");

    reader = sq_reader_from_bytes((const uint8_t *) ctext, csize);
    if (! reader)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "Creating reader");

    writer = sq_writer_alloc((void **) ptext, psize);
    if (! writer)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Creating writer");

    sq_status_t sq_status = sq_decrypt(session->ctx, reader, writer,
                                       get_public_keys_cb, get_secret_keys_cb,
                                       check_signatures_cb, &cookie);
    if (sq_status)
        ERROR_OUT(session, PEP_DECRYPT_NO_KEY, "sq_decrypt");

    if (! cookie.decrypted)
        ERROR_OUT(session, PEP_DECRYPT_NO_KEY, "Decryption failed");

    // Add a terminating NUL for naive users
    void *t = realloc(*ptext, *psize + 1);
    if (! t)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");
    *ptext = t;
    (*ptext)[*psize] = 0;

    if (! cookie.signer_keylist) {
        cookie.signer_keylist = new_stringlist("");
        if (! cookie.signer_keylist)
            ERROR_OUT(session, PEP_OUT_OF_MEMORY, "cookie.signer_keylist");
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
        sq_reader_free(reader);
    if (writer)
        sq_writer_free(writer);

    T("-> %s", pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist)
{
    PEP_STATUS status = PEP_STATUS_OK;
    struct decrypt_cookie cookie = { session, 0, NULL, NULL, 0, 0, 0, };
    sq_reader_t reader = NULL;
    sq_reader_t dsig_reader = NULL;

    if (size == 0 || sig_size == 0)
        return PEP_DECRYPT_WRONG_FORMAT;

    cookie.recipient_keylist = new_stringlist(NULL);
    if (!cookie.recipient_keylist)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");

    cookie.signer_keylist = new_stringlist(NULL);
    if (!cookie.signer_keylist)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");

    reader = sq_reader_from_bytes((const uint8_t *) text, size);
    if (! reader)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "Creating reader");

    dsig_reader = NULL;
    if (signature) {
        dsig_reader = sq_reader_from_bytes((uint8_t *) signature, sig_size);
        if (! dsig_reader)
            ERROR_OUT(session, PEP_OUT_OF_MEMORY, "Creating signature reader");
    }

    if (sq_verify(session->ctx, reader, dsig_reader, /* output */ NULL,
                  get_public_keys_cb, check_signatures_cb, &cookie))
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "sq_verify");

    if (! cookie.signer_keylist) {
        cookie.signer_keylist = new_stringlist("");
        if (! cookie.signer_keylist)
            ERROR_OUT(session, PEP_OUT_OF_MEMORY, "cookie.signer_keylist");
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
        sq_reader_free(reader);
    if (dsig_reader)
        sq_reader_free(dsig_reader);

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

    PEP_STATUS status = PEP_STATUS_OK;
    sq_tsk_t signer = NULL;
    sq_tpk_t signer_tpk = NULL; /* Reference.  */
    sq_writer_stack_t ws = NULL;

    status = tsk_find_by_fpr_hex(session, fpr, &signer);
    ERROR_OUT(session, status, "Looking up key '%s'", fpr);
    signer_tpk = sq_tsk_tpk(signer);

    sq_writer_t writer = sq_writer_alloc((void **) stext, ssize);
    writer = sq_armor_writer_new(session->ctx, writer,
                                 SQ_ARMOR_KIND_MESSAGE, NULL, 0);
    if (!writer)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Setting up armor writer");

    ws = sq_writer_stack_message(writer);

    ws = sq_signer_new_detached(session->ctx, ws, &signer_tpk, 1);
    if (!ws)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Setting up signer");

    sq_status_t write_status =
        sq_writer_stack_write_all (session->ctx, ws,
                                   (uint8_t *) ptext, psize);
    if (write_status != 0)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Encrypting message");

    // Add a terminating NUL for naive users
    void *t = realloc(*stext, *ssize + 1);
    if (! t)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");
    *stext = t;
    (*stext)[*ssize] = 0;

 out:
    if (ws) {
        sq_status_t sq_status = sq_writer_stack_finalize (session->ctx, ws);
        ws = NULL;
        if (sq_status != 0)
            ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Flushing writer");
    }

    if (signer)
        sq_tsk_free(signer);

    T("(%s)-> %s", fpr, pep_status_to_string(status));
    return status;
}

static PEP_STATUS pgp_encrypt_sign_optional(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize, bool sign)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int keys_count = 0;
    sq_tpk_t *keys = NULL;
    sq_tsk_t signer = NULL;
    sq_tpk_t signer_tpk = NULL; /* Reference. */
    sq_writer_stack_t ws = NULL;

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
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");

    // Get the keys for the recipients.
    const stringlist_t *_keylist;
    for (_keylist = keylist; _keylist != NULL; _keylist = _keylist->next) {
        assert(_keylist->value);
        sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(_keylist->value);
        status = tpk_find_by_fpr(session, sq_fpr, &keys[keys_count ++]);
        sq_fingerprint_free(sq_fpr);
        ERROR_OUT(session, status, "Looking up key '%s'", _keylist->value);
    }

    if (sign) {
        // The first key in the keylist is the signer.
        status = tsk_find_by_fpr_hex(session, keylist->value, &signer);
        ERROR_OUT(session, status, "Looking up key '%s'", keylist->value);
        signer_tpk = sq_tsk_tpk(signer);
    }

    sq_writer_t writer = sq_writer_alloc((void **) ctext, csize);
    writer = sq_armor_writer_new(session->ctx, writer,
                                 SQ_ARMOR_KIND_MESSAGE, NULL, 0);
    if (!writer)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Setting up armor writer");

    ws = sq_writer_stack_message(writer);
    ws = sq_encryptor_new (session->ctx, ws,
                           NULL, 0, keys, keys_count,
                           SQ_ENCRYPTION_MODE_FOR_TRANSPORT);
    if (!ws) {
        sq_writer_free(writer);
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Setting up encryptor");
    }

    if (sign) {
        ws = sq_signer_new(session->ctx, ws, &signer_tpk, 1);
        if (!ws)
            ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Setting up signer");
    }

    ws = sq_literal_writer_new (session->ctx, ws);
    if (!ws)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Setting up literal writer");

    sq_status_t write_status =
        sq_writer_stack_write_all (session->ctx, ws,
                                   (uint8_t *) ptext, psize);
    if (write_status != 0)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Encrypting message");

    // Add a terminating NUL for naive users
    void *t = realloc(*ctext, *csize + 1);
    if (! t)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "out of memory");
    *ctext = t;
    (*ctext)[*csize] = 0;

 out:
    if (ws) {
        sq_status_t sq_status = sq_writer_stack_finalize (session->ctx, ws);
        ws = NULL;
        if (sq_status != 0)
            ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Flushing writer");
    }

    if (signer)
        sq_tsk_free(signer);
    for (int i = 0; i < keys_count; i ++)
        sq_tpk_free(keys[i]);
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
    char *userid = NULL;
    sq_tpk_t tpk = NULL;
    sq_fingerprint_t sq_fpr = NULL;
    char *fpr = NULL;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->fpr == NULL || identity->fpr[0] == 0);
    assert(identity->username);

    asprintf(&userid, "%s <%s>", identity->username, identity->address);
    if (! userid)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "asprintf");

    // Generate a key.
    sq_tsk_t tsk;
    sq_signature_t rev;
    if (sq_tsk_new(session->ctx, userid, &tsk, &rev) != 0)
        ERROR_OUT(session, PEP_CANNOT_CREATE_KEY, "Generating a key pair");

    // XXX: We should return this.
    // sq_signature_free(rev);

    tpk = sq_tsk_into_tpk(tsk);

    // Get the fingerprint.
    sq_fpr = sq_tpk_fingerprint(tpk);
    fpr = sq_fingerprint_to_hex(sq_fpr);

    status = tpk_save(session, tpk, identity->address, NULL, 1);
    tpk = NULL;
    if (status != 0)
        ERROR_OUT(session, PEP_CANNOT_CREATE_KEY, "saving TSK");

    free(identity->fpr);
    identity->fpr = fpr;
    fpr = NULL;

 out:
    if (sq_fpr)
        sq_fingerprint_free(sq_fpr);
    free(fpr);
    if (tpk)
        sq_tpk_free(tpk);
    free(userid);

    T("-> %s", pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_delete_keypair(PEP_SESSION session, const char *fpr_raw)
{
    PEP_STATUS status = PEP_STATUS_OK;
    char *fpr = sq_fingerprint_canonicalize(fpr_raw);

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

    if (private_idents)
        *private_idents = NULL;

    T("parsing %zd bytes", size);

    sq_packet_parser_result_t ppr
        = sq_packet_parser_from_bytes(session->ctx, (uint8_t *) key_data, size);
    if (! ppr)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "Creating packet parser");

    sq_tag_t tag = sq_packet_parser_result_tag(ppr);
    switch (tag) {
    case SQ_TAG_SIGNATURE:
        // XXX: Implement me.
        assert(!"Have possible revocation certificate!");
        break;

    case SQ_TAG_PUBLIC_KEY:
    case SQ_TAG_SECRET_KEY: {
        sq_tpk_t tpk = sq_tpk_from_packet_parser(session->ctx, ppr);
        if (! tpk)
            ERROR_OUT(session, PEP_UNKNOWN_ERROR, "parsing key data");

        // If private_idents is not NULL and there is any private key
        // material, it will be saved.
        status = tpk_save(session, tpk, NULL, private_idents, false);
        ERROR_OUT(session, status, "saving TPK");

        break;
    }
    default:
        ERROR_OUT(session, PEP_STATUS_OK,
                  "Can't import %s", sq_tag_to_string(tag));
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
    sq_tpk_t secret_key = NULL;
    sq_tpk_t tpk = NULL;

    assert(session);
    assert(fpr);
    assert(key_data);
    assert(*key_data == NULL);
    assert(size);

    *size = 0;

    T("(%s, %s)", fpr, secret ? "secret" : "public");

    if (secret) {
        sq_tsk_t tsk;
        status = tsk_find_by_fpr_hex(session, fpr, &tsk);
        if (status == PEP_KEY_NOT_FOUND) {
            status = PEP_STATUS_OK;
        } else if (status == PEP_STATUS_OK) {
            secret_key = sq_tsk_into_tpk(tsk);
        } else {
            ERROR_OUT(session, status, "Looking up TSK");
        }
    }

    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, sq_fpr, &tpk);
    sq_fingerprint_free(sq_fpr);
    ERROR_OUT(session, status, "Looking up TPK for %s", fpr);

    if (secret_key) {
        tpk = sq_tpk_merge(session->ctx, tpk, secret_key);
        // sq_tpk_merge can return NULL if the primary keys don't
        // match.  But, we looked up the tpk by the secret key's
        // fingerprint so this should not be possible.
        assert(tpk);
        secret_key = NULL;
    }

    sq_writer_t memory_writer = sq_writer_alloc((void **) key_data, size);
    if (! memory_writer)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "creating memory writer");
    sq_writer_t armor_writer = sq_armor_writer_new(session->ctx,
                                                   memory_writer,
                                                   SQ_ARMOR_KIND_PUBLICKEY,
                                                   NULL, 0);
    if (! armor_writer) {
        sq_writer_free(memory_writer);
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "creating armored writer");
    }

    if (secret) {
        sq_tsk_t tsk = sq_tpk_into_tsk(tpk);
        sq_tsk_serialize(session->ctx, tsk, armor_writer);
        tpk = sq_tsk_into_tpk(tsk);
    } else {
        sq_tpk_serialize(session->ctx, tpk, armor_writer);
    }

 out:
    if (tpk)
        sq_tpk_free(tpk);

    if (armor_writer)
        sq_writer_free(armor_writer);

    if (secret_key)
        sq_tpk_free(secret_key);

    T("(%s) -> %s", fpr, pep_status_to_string(status));
    return status;
}

static stringpair_list_t *add_key(PEP_SESSION session, stringpair_list_t *k,
                                  sq_tpk_t tpk, sq_fingerprint_t fpr) {
    sq_revocation_status_t rs = sq_tpk_revocation_status(tpk);
    sq_revocation_status_variant_t rsv = sq_revocation_status_variant(rs);
    sq_revocation_status_free(rs);
    if (rsv == SQ_REVOCATION_STATUS_REVOKED)
        return k;

    int dealloc_fpr = 0;
    if (!fpr) {
        dealloc_fpr = 1;
        fpr = sq_tpk_fingerprint(tpk);
    }

    char *fpr_str = sq_fingerprint_to_hex(fpr);
    char *user_id = sq_tpk_primary_user_id(tpk);
    if (user_id) {
        T("  %s -> %s", fpr_str, user_id);
        k = stringpair_list_add(k, new_stringpair(fpr_str, user_id));
    }

    free(user_id);
    free(fpr_str);
    if (dealloc_fpr)
        sq_fingerprint_free(fpr);

    return k;
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
    PEP_STATUS status = PEP_STATUS_OK;
    sq_tpk_t tpk = NULL;
    sq_fingerprint_t fpr = NULL;

    T("('%s')", pattern);

    *keyinfo_list = new_stringpair_list(NULL);
    if (!*keyinfo_list)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "new_stringlist");

    // Trim any leading space.  This also makes it easier to recognize
    // a string that is only whitespace.
    while (*pattern == ' ')
        pattern ++;

    if (strchr(pattern, '@')) {
        // Looks like a mailbox.
        status = tpk_find_by_label(session, pattern, &tpk);
        ERROR_OUT(session, status, "Looking up '%s'", pattern);
        add_key(session, *keyinfo_list, tpk, NULL);

        assert(!"pgp_list_keyinfo(email) untested, please make a test case");
    } else if (// Only hex characters and spaces
               pattern[strspn(pattern, "0123456789aAbBcCdDeEfF ")] == 0
               // And a fair amount of them.
               && strlen(pattern) >= 16) {
        // Fingerprint.
        fpr = sq_fingerprint_from_hex(pattern);
        status = tpk_find_by_fpr(session, fpr, &tpk);
        ERROR_OUT(session, status, "Looking up key");
        add_key(session, *keyinfo_list, tpk, fpr);

        assert(!"pgp_list_keyinfo(fpr) untested, please make a test case");
    } else if (pattern[0] == 0) {
        // Empty string.
        sq_binding_iter_t iter = sq_store_iter(session->ctx, session->store);
        sq_binding_t binding;
        char *label;
        stringpair_list_t *_k = *keyinfo_list;
        while ((binding = sq_binding_iter_next(iter, &label, &fpr))) {
            if (strchr(label, '@')) {
                char *fpr_str = sq_fingerprint_to_hex(fpr);
                T("  %s -> %s", fpr_str, label);
                _k = stringpair_list_add(_k, new_stringpair(fpr_str, label));
                free(fpr_str);
            }
            free(label);
            sq_fingerprint_free(fpr);
            fpr = NULL;
            sq_binding_free(binding);
        }
        sq_binding_iter_free(iter);
    }

 out:
    if (tpk)
        sq_tpk_free(tpk);
    if (fpr)
        sq_fingerprint_free(fpr);
    if (status != PEP_STATUS_OK && *keyinfo_list) {
        free_stringpair_list(*keyinfo_list);
        *keyinfo_list = NULL;
    }
    if (status == PEP_KEY_NOT_FOUND)
        status = PEP_STATUS_OK;

    T("(%s) -> %s", pattern, pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_recv_key(PEP_SESSION session, const char *pattern)
{
    assert(!"pgp_recv_key not implemented");
    return PEP_UNKNOWN_ERROR;
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

// Unlike pgp_list_keyinfo, this function returns revoked keys.
static PEP_STATUS _pgp_search_keys(PEP_SESSION session, const char* pattern,
                                   stringlist_t** keylist, int private_only) {
    PEP_STATUS status = PEP_STATUS_OK;
    sq_binding_t binding = NULL;
    sq_tpk_t tpk = NULL;
    sq_fingerprint_t fingerprint = NULL;
    char *fingerprint_hex = NULL;

    *keylist = NULL;

    // XXX: We only return an exact match.
    T("(pattern: %s, private_only: %d)", pattern, private_only);

    binding = sq_store_lookup(session->ctx, session->store, pattern);
    if (! binding) {
        // No binding is not an error: it means there is no match.
        if (pattern != NULL) {
            // If match failed, check to see if we've got a dotted
            // address in the pattern.  If so, try again without dots.
            const char* dotpos = strstr(pattern, ".");
            const char* atpos = strstr(pattern, "@");
            if (dotpos && atpos && (dotpos < atpos)) {
                char* undotted = _undot_address(pattern);
                if (undotted) {
                    PEP_STATUS status = _pgp_search_keys(session, undotted,
                                                         keylist, private_only);
                    free(undotted);
                    return status;
                }
            }
        }
        goto out;
    }

    tpk = sq_binding_tpk(session->ctx, binding);
    if (! tpk)
        ERROR_OUT(session, PEP_GET_KEY_FAILED, "Getting TPK");

    fingerprint = sq_tpk_fingerprint(tpk);
    if (!fingerprint)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "Getting fingerprint");

    if (private_only) {
        // See if we have the private key.
        status = tsk_find_by_fpr(session, fingerprint, NULL);
        ERROR_OUT(session, status, "No private key material");
    }

    fingerprint_hex = sq_fingerprint_to_hex(fingerprint);
    if (!fingerprint_hex)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "sq_fingerprint_to_hex");

    stringlist_t *_keylist = new_stringlist(fingerprint_hex);
    if (_keylist == NULL)
        ERROR_OUT(session, PEP_OUT_OF_MEMORY, "new_stringlist");
    *keylist = _keylist;

 out:
    free(fingerprint_hex);
    if (fingerprint)
        sq_fingerprint_free(fingerprint);
    if (tpk)
        sq_tpk_free(tpk);
    if (binding)
        sq_binding_free(binding);

    T("(pattern: %s, private_only: %d) -> %s",
      pattern, private_only, pep_status_to_string(status));
    return status;
}

PEP_STATUS pgp_find_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist)
{
    return _pgp_search_keys(session, pattern, keylist, 0);
}

PEP_STATUS pgp_find_private_keys(
    PEP_SESSION session, const char *pattern, stringlist_t **keylist)
{
    return _pgp_search_keys(session, pattern, keylist, 1);
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
    sq_tpk_t tpk = NULL;

    assert(session);
    assert(fpr);
    assert(comm_type);

    *comm_type = PEP_ct_unknown;

    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, sq_fpr, &tpk);
    sq_fingerprint_free(sq_fpr);
    ERROR_OUT(session, status, "Looking up key: %s", fpr);

    *comm_type = PEP_ct_OpenPGP_unconfirmed;

    if (sq_tpk_expired(tpk)) {
        *comm_type = PEP_ct_key_expired;
        goto out;
    }

    sq_revocation_status_t rs = sq_tpk_revocation_status(tpk);
    sq_revocation_status_variant_t rsv = sq_revocation_status_variant(rs);
    sq_revocation_status_free(rs);
    if (rsv == SQ_REVOCATION_STATUS_REVOKED) {
        *comm_type = PEP_ct_key_revoked;
        goto out;
    }

    PEP_comm_type best_enc = PEP_ct_no_encryption, best_sign = PEP_ct_no_encryption;
    sq_tpk_key_iter_t key_iter = sq_tpk_key_iter(tpk);
    sq_p_key_t key;
    sq_signature_t sig;
    sq_revocation_status_t rev;
    while ((key = sq_tpk_key_iter_next(key_iter, &sig, &rev))) {
        if (! sig)
            continue;

        if (sq_revocation_status_variant(rev) == SQ_REVOCATION_STATUS_REVOKED)
            continue;

        if (! sq_p_key_alive(key, sig))
            continue;

        PEP_comm_type curr = PEP_ct_no_encryption;

        int can_enc = sq_signature_can_encrypt_for_transport(sig)
            || sq_signature_can_encrypt_at_rest(sig);
        int can_sign = sq_signature_can_sign(sig);

        sq_public_key_algo_t pk_algo = sq_p_key_public_key_algo(key);
        if (pk_algo == SQ_PUBLIC_KEY_ALGO_RSA_ENCRYPT_SIGN
            || pk_algo == SQ_PUBLIC_KEY_ALGO_RSA_ENCRYPT
            || pk_algo == SQ_PUBLIC_KEY_ALGO_RSA_SIGN) {
            int bits = sq_p_key_public_key_bits(key);
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
    sq_tpk_key_iter_free(key_iter);

    if (best_enc == PEP_ct_no_encryption || best_sign == PEP_ct_no_encryption) {
        *comm_type = PEP_ct_key_b0rken;
        goto out;
    } else {
        *comm_type = _MIN(best_enc, best_sign);
    }

 out:
    if (tpk)
        sq_tpk_free(tpk);

    T("(%s) -> %s", fpr, pep_comm_type_to_string(*comm_type));
    return status;
}


PEP_STATUS pgp_renew_key(
    PEP_SESSION session, const char *fpr, const timestamp *ts)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_tsk_t tsk = NULL;
    sq_tpk_t tpk = NULL;

    time_t t = mktime((struct tm *) ts);

    status = tsk_find_by_fpr_hex(session, fpr, &tsk);
    ERROR_OUT(session, status, "Looking up '%s'", fpr);

    tpk = sq_tsk_into_tpk(tsk);

    uint32_t creation_time = sq_p_key_creation_time(sq_tpk_primary(tpk));
    if (creation_time > t)
        // The creation time is after the expiration time!
        ERROR_OUT(session, PEP_UNKNOWN_ERROR,
                  "creation time can't be after expiration time");

    uint32_t delta = t - creation_time;
    tpk = sq_tpk_set_expiry(session->ctx, tpk, delta);
    if (! tpk)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "setting expiration");

    status = tpk_save(session, tpk, NULL, NULL, false);
    tpk = NULL;
    ERROR_OUT(session, status, "Saving %s", fpr);

 out:
    if (tpk)
        sq_tpk_free(tpk);

    return status;
}

PEP_STATUS pgp_revoke_key(
    PEP_SESSION session, const char *fpr, const char *reason)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_tsk_t tsk = NULL;
    sq_tpk_t tpk = NULL;

    status = tsk_find_by_fpr_hex(session, fpr, &tsk);
    ERROR_OUT(session, status, "Looking up %s", fpr);

    tpk = sq_tsk_into_tpk(tsk);
    tpk = sq_tpk_revoke_in_place(session->ctx, tpk,
                                 SQ_REASON_FOR_REVOCATION_UNSPECIFIED,
                                 reason);
    if (! tpk)
        ERROR_OUT(session, PEP_UNKNOWN_ERROR, "setting expiration");

    assert(sq_revocation_status_variant(sq_tpk_revocation_status(tpk))
           == SQ_REVOCATION_STATUS_REVOKED);

    status = tpk_save(session, tpk, NULL, NULL, false);
    tpk = NULL;
    ERROR_OUT(session, status, "Saving %s", fpr);

 out:
    if (tpk)
        sq_tpk_free(tpk);

    return status;
}

PEP_STATUS pgp_key_expired(PEP_SESSION session, const char *fpr,
                           const time_t when, bool *expired)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_tpk_t tpk = NULL;

    assert(session);
    assert(fpr);
    assert(expired);

    *expired = false;

    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, sq_fpr, &tpk);
    sq_fingerprint_free(sq_fpr);
    ERROR_OUT(session, status, "Looking up %s", fpr);

    // Is the TPK live?
    *expired = !sq_tpk_alive_at(tpk, when);
    if (*expired)
        goto out;

    // Are there at least one certification subkey, one signing subkey
    // and one encryption subkey that are live?
    int can_certify = 0, can_encrypt = 0, can_sign = 0;

    sq_tpk_key_iter_t key_iter = sq_tpk_key_iter(tpk);
    sq_p_key_t key;
    sq_signature_t sig;
    sq_revocation_status_t rev;
    while ((key = sq_tpk_key_iter_next(key_iter, &sig, &rev))) {
        if (! sig)
            continue;

        if (sq_revocation_status_variant(rev) == SQ_REVOCATION_STATUS_REVOKED)
            continue;

        if (!sq_p_key_alive_at(key, sig, when))
            continue;

        if (sq_signature_can_encrypt_for_transport(sig)
            || sq_signature_can_encrypt_at_rest(sig))
            can_encrypt = 1;
        if (sq_signature_can_sign(sig))
            can_sign = 1;
        if (sq_signature_can_certify(sig))
            can_certify = 1;

        if (can_encrypt && can_sign && can_certify)
            break;
    }
    sq_tpk_key_iter_free(key_iter);

    *expired = !(can_encrypt && can_sign && can_certify);

 out:
    if (tpk)
        sq_tpk_free(tpk);
    return status;
}

PEP_STATUS pgp_key_revoked(PEP_SESSION session, const char *fpr, bool *revoked)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_tpk_t tpk;

    assert(session);
    assert(fpr);
    assert(revoked);

    *revoked = false;

    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, sq_fpr, &tpk);
    sq_fingerprint_free(sq_fpr);
    ERROR_OUT(session, status, "Looking up %s", fpr);

    sq_revocation_status_t rs = sq_tpk_revocation_status(tpk);
    *revoked = sq_revocation_status_variant(rs) == SQ_REVOCATION_STATUS_REVOKED;
    sq_revocation_status_free (rs);
    sq_tpk_free(tpk);

 out:
    return status;
}

PEP_STATUS pgp_key_created(PEP_SESSION session, const char *fpr, time_t *created)
{
    PEP_STATUS status = PEP_STATUS_OK;
    sq_tpk_t tpk = NULL;

    *created = 0;

    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    status = tpk_find_by_fpr(session, sq_fpr, &tpk);
    sq_fingerprint_free(sq_fpr);
    ERROR_OUT(session, status, "Looking up %s", fpr);

    sq_p_key_t k = sq_tpk_primary(tpk);
    *created = sq_p_key_creation_time(k);
    sq_tpk_free(tpk);

 out:
    return status;
}

PEP_STATUS pgp_binary(const char **path)
{
    return PEP_STATUS_OK;
}

PEP_STATUS pgp_contains_priv_key(PEP_SESSION session, const char *fpr,
                                 bool *has_private)
{
    sq_fingerprint_t sq_fpr = sq_fingerprint_from_hex(fpr);
    PEP_STATUS status = tsk_find_by_fpr(session, sq_fpr, NULL);
    sq_fingerprint_free(sq_fpr);
    if (status == PEP_STATUS_OK) {
        *has_private = 1;
        return PEP_STATUS_OK;
    } else if (status == PEP_KEY_NOT_FOUND) {
        *has_private = 0;
        return PEP_STATUS_OK;
    } else {
        return status;
    }
}
