// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "cryptotech.h"
#include "transport.h"
#include "blacklist.h"
#include "KeySync_fsm.h"
#include "pEp/status_to_string.h"

#include <time.h>
#include <stdlib.h>

#ifdef _PEP_SQLITE_DEBUG
#include <sqlite3.h>
#endif

static void normalize_address(sqlite3_context *context,
                              int argc,
                              sqlite3_value **argv)
{
#define FAIL(error_code, message)                                \
    do                                                           \
        {                                                        \
            sqlite3_result_error(context, message, error_code);  \
            return;                                              \
        }                                                        \
    while (false)
    // FIXME: useful: sqlite3_result_error_nomem()
    // FIXME: useful: sqlite3_result_error_toobig()
    // FIXME: useful: sqlite3_result_text(context, res, -1, SQLITE_TRANSIENT);

    if (sqlite3_value_type(argv[0]) != SQLITE_TEXT)
        FAIL (SQLITE_MISMATCH, "type error");

    /* Make a copy of the argument, skipping an optional «mailto:» prefix. */
    const char *argument = sqlite3_value_text(argv[0]);
    //printf ("argument: \"%s\"\n", argument);
    if (strstr (argument, "mailto:") == argument)
        argument += 7;
    size_t length = strlen (argument);
    char *res = calloc (length + 1, 1);
    if (res == NULL)
        FAIL (SQLITE_NOMEM, "out of memory");
    int from_i, to_i;
    char c;
    for (from_i = 0, to_i = 0;
         from_i < length;
         from_i ++)
        switch (argument [from_i]) {
        case '.':
            /* Do nothing. */
            break;
        default:
            res [to_i ++] = tolower (argument [from_i]);
        }
    res [to_i] = '\0';
    /* //strncpy (res, argument, length + 1); */
    /* int i; */
    /* for (i = 0; i < length; i ++) */
    /*     res [i] = tolower (res [i]); */
    
    //FAIL (SQLITE_NOMEM, "out of memory");
    //FAIL (SQLITE_MISMATCH, "type error");
    sqlite3_result_text(context, res, -1, SQLITE_TRANSIENT);
    free (res);
    return;
#undef FAIL
}

static PEP_STATUS _initialize_sql_extension (sqlite3 *db)
{
    int sql_result
        = sqlite3_create_function_v2(db, "normalize_address", 1,
                                     SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,
                                     NULL,  // pApp
                                     normalize_address,  // xFunc
                                     NULL,  // xStep
                                     NULL,  // xFinal
                                     NULL); // xDestroy
    if (sql_result == SQLITE_OK)
        return PEP_STATUS_OK;
    else
        return PEP_INIT_CANNOT_OPEN_DB; /* Not really, but not too far either. */
}

void
reset_and_clear_bindings(sqlite3_stmt *s)
{
    sqlite3_reset(s);
    sqlite3_clear_bindings(s);
} 

/* Return true iff the pointed string is a temporary user-id. */
static bool _is_temporary_user_id(const char *s)
{
    assert(s != NULL);
    if (s == NULL) {
        fprintf (stderr, "%s: NULL\n", __FUNCTION__);
        abort();
    }
    return ((const char *) strstr(s, "TOFU_") == s);
}

static volatile int init_count = -1;

// sql overloaded functions - modified from sqlite3.c
static void _sql_lower(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
    const char *z2;
    int n;
    z2 = (char*)sqlite3_value_text(argv[0]);
    n = sqlite3_value_bytes(argv[0]);
    /* Verify that the call to _bytes() does not invalidate the _text() pointer */
    assert( z2==(char*)sqlite3_value_text(argv[0]) );
    if( z2 ){
        char *z1 = (char*)sqlite3_malloc(n+1);
        if( z1 ){
            for(int i=0; i<n; i++){
                char c = z2[i];
                char c_mod = c | 0x20;
                if (c_mod < 0x61 || c_mod > 0x7a)
                    c_mod = c;
                z1[i] = c_mod;
            }
            z1[n] = '\0';
            sqlite3_result_text(ctx, z1, n, sqlite3_free);
        }
    }
}

#ifdef _PEP_SQLITE_DEBUG
int sql_trace_callback (unsigned trace_constant, 
                        void* context_ptr,
                        void* P,
                        void* X) {
    switch (trace_constant) {
        case SQLITE_TRACE_STMT:
            fprintf(stderr, "SQL_DEBUG: STMT - ");
            const char* X_str = (const char*) X;
            if (!EMPTYSTR(X_str) && X_str[0] == '-' && X_str[1] == '-')
                fprintf(stderr, "%s\n", X_str);
            else
                fprintf(stderr, "%s\n", sqlite3_expanded_sql((sqlite3_stmt*)P));    
            break;
        case SQLITE_TRACE_ROW:
            fprintf(stderr, "SQL_DEBUG: ROW - ");
            fprintf(stderr, "%s\n", sqlite3_expanded_sql((sqlite3_stmt*)P));
            break;            
        case SQLITE_TRACE_CLOSE:
            fprintf(stderr, "SQL_DEBUG: CLOSE - ");
            break;
        default:
            break;
    }
    return 0;
}
#endif

// sql manipulation statements
static const char *sql_log = 
    "insert into log (title, entity, description, comment)"
     "values (?1, ?2, ?3, ?4);";

static const char *sql_trustword = 
    "select id, word from wordlist where lang = lower(?1) "
    "and id = ?2 ;";

// FIXME?: problems if we don't have a key for the user - we get nothing
static const char *sql_get_identity =  
    "select identity.main_key_id, username, comm_type, lang,"
    "   identity.flags | pgp_keypair.flags,"
    "   is_own, pEp_version_major, pEp_version_minor, enc_format"
    "   from identity"
    "   join person on id = identity.user_id"
    "   left join pgp_keypair on fpr = identity.main_key_id"
    "   left join trust on id = trust.user_id"
    "       and pgp_keypair_fpr = identity.main_key_id"    
    "   where normalize_address (?1) = normalize_address (address)"
    "   and identity.user_id = ?2" 
    "   order by is_own desc, "
    "   timestamp desc; ";

static const char *sql_get_identities_by_main_key_id =  
    "select address, identity.user_id, username, comm_type, lang,"
    "   identity.flags | pgp_keypair.flags,"
    "   is_own, pEp_version_major, pEp_version_minor, enc_format"
    "   from identity"
    "   join person on id = identity.user_id"
    "   left join pgp_keypair on fpr = identity.main_key_id"
    "   left join trust on id = trust.user_id"
    "       and pgp_keypair_fpr = identity.main_key_id"    
    "   where identity.main_key_id = ?1" 
    "   order by is_own desc, "
    "   timestamp desc; ";

static const char *sql_get_identity_without_trust_check =  
    "select identity.main_key_id, username, lang,"
    "   identity.flags, is_own, pEp_version_major, pEp_version_minor, enc_format"
    "   from identity"
    "   join person on id = identity.user_id"
    "   where normalize_address (?1) = normalize_address (address) "
    "   and identity.user_id = ?2 "
    "   order by is_own desc, "
    "   timestamp desc; ";

static const char *sql_get_identities_by_address =  
    "select user_id, identity.main_key_id, username, lang,"
    "   identity.flags, is_own, pEp_version_major, pEp_version_minor, enc_format"
    "   from identity"
    "   join person on id = identity.user_id"
    "   where normalize_address (?1) = normalize_address (address) "
    "   order by is_own desc, "
    "   timestamp desc; ";
    
static const char *sql_get_identities_by_userid =  
    "select address, identity.main_key_id, username, comm_type, lang,"
    "   identity.flags | pgp_keypair.flags,"
    "   is_own, pEp_version_major, pEp_version_minor, enc_format"
    "   from identity"
    "   join person on id = identity.user_id"
    "   left join pgp_keypair on fpr = identity.main_key_id"
    "   left join trust on id = trust.user_id"
    "       and pgp_keypair_fpr = identity.main_key_id"    
    "   where identity.user_id = ?1" 
    "   order by is_own desc, "
    "   timestamp desc; ";

static const char *sql_replace_identities_fpr =  
    "update identity"
    "   set main_key_id = ?1 "
    "   where main_key_id = ?2 ;";

static const char* sql_set_default_identity_fpr =
        "update identity set main_key_id = ?3 "
        "    where user_id = ?1 and address = ?2; ";

static const char *sql_get_default_identity_fpr =
        "select main_key_id from identity"
        "   where  normalize_address (?1) = normalize_address (address) "
        "          and user_id = ?2 ;";

static const char *sql_remove_fpr_as_identity_default =
    "update identity set main_key_id = NULL where main_key_id = ?1 ;";

static const char *sql_remove_fpr_as_user_default =
    "update person set main_key_id = NULL where main_key_id = ?1 ;";
    
// Set person, but if already exist, only update.
// if main_key_id already set, don't touch.
static const char *sql_set_person = 
     "insert into person (id, username, lang, main_key_id)"
     "  values (?1, ?2, ?3, ?4) ;";

static const char *sql_update_person = 
    "update person "
    "   set username = ?2, "
    "       lang = ?3, "
    "       main_key_id =  "
    "           (select coalesce( "
    "               (select main_key_id from person where id = ?1), " 
    "                upper(replace(?4,' ',''))))"         
    "   where id = ?1 ;";

// Will cascade.
static const char *sql_delete_person = 
     "delete from person where id = ?1 ;";

static const char *sql_set_as_pEp_user =
    "update person set is_pEp_user = 1 "
    "   where id = ?1 ; ";

static const char *sql_is_pEp_user =
    "select is_pEp_user from person "
    "   where id = ?1 ; ";

static const char* sql_exists_person = 
    "select count(*) from person "
    "   where id = ?1 ;";

// This will cascade to identity and trust
static const char* sql_replace_userid =
    "update person set id = ?1 " 
    "   where id = ?2;";

// Hopefully this cascades and removes trust entries...
static const char *sql_delete_key =
    "delete from pgp_keypair "
    "   where fpr = ?1 ; ";

static const char *sql_replace_main_user_fpr =  
    "update person "
    "   set main_key_id = ?1 "
    "   where id = ?2 ;";

static const char *sql_get_main_user_fpr =  
    "select main_key_id from person"
    "   where id = ?1 ;";

static const char *sql_replace_main_user_fpr_if_equal =  
    "update person "
    "   set main_key_id = ?1 "
    "   where id = ?2 and main_key_id = ?3;";

static const char *sql_refresh_userid_default_key =
    "update person "
    "   set main_key_id = "
    "       (select identity.main_key_id from identity "
    "           join trust on trust.user_id = identity.user_id "
    "               and trust.pgp_keypair_fpr = identity.main_key_id "
    "           join person on person.id = identity.user_id "
    "       where identity.user_id = ?1 "
    "       order by trust.comm_type desc "
    "       limit 1) "
    "where id = ?1 ; ";

static const char *sql_set_pgp_keypair = 
    "insert or ignore into pgp_keypair (fpr) "
    "values (upper(replace(?1,' ',''))) ;";

static const char* sql_exists_identity_entry = 
    "select count(*) from identity "
    "   where normalize_address (?1) = normalize_address (address) "
    "   and user_id = ?2;";
 
static const char *sql_set_identity_entry = 
    "insert into identity ("
    "       address, main_key_id, "
    "       user_id, flags, is_own,"
    "       pEp_version_major, pEp_version_minor"
    "   ) values ("
    "       ?1,"
    "       upper(replace(?2,' ','')),"
    "       ?3,"
    "       ?4,"
    "       ?5,"
    "       ?6,"
    "       ?7"
    "   );";
    
static const char* sql_update_identity_entry =    
    "update identity "
    "   set main_key_id = upper(replace(?2,' ','')), "
    "       flags = ?4, " 
    "       is_own = ?5, "
    "       pEp_version_major = ?6, "
    "       pEp_version_minor = ?7 "    
    "   where normalize_address (?1) = normalize_address (address) "
    "          and user_id = ?3 ;";

    // " (select"
    // "   coalesce("
    // "    (select flags from identity"
    // "     where address = ?1 and"
    // "           user_id = ?3),"
    // "    0)"
    // " ) | (?4 & 255)"
    /* set_identity ignores previous flags, and doesn't filter machine flags */
        
static const char *sql_set_identity_flags = 
    "update identity set flags = "
    "    ((?1 & 65535) | (select flags from identity"
    "                     where normalize_address (?2) = normalize_address (address) "
    "                           and user_id = ?3)) "
    "   where normalize_address (?2) = normalize_address (address) "
    "         and user_id = ?3 ;";

static const char *sql_unset_identity_flags = 
    "update identity set flags = "
    "    ( ~(?1 & 65535) & (select flags from identity"
    "                    where normalize_address (?2) = normalize_address (address) "
    "                          and user_id = ?3)) "
    "   where normalize_address (?2) = normalize_address (address) "
    "         and user_id = ?3 ;";

static const char *sql_set_ident_enc_format =
    "update identity "
    "   set enc_format = ?1 "
    "   where normalize_address (?2) = normalize_address (address) "
    "         and user_id = ?3 ;";

static const char *sql_set_pEp_version =
    "update identity "
    "   set pEp_version_major = ?1, "
    "       pEp_version_minor = ?2 "
    "   where normalize_address (?3) = normalize_address (address) "
    "         and user_id = ?4 ;";

static const char *sql_upgrade_pEp_version_by_user_id =
    "update identity "
    "   set pEp_version_major = ?1, "
    "       pEp_version_minor = ?2 "
    "       where user_id = ?3 "
    "           and (case when (pEp_version_major < ?1) then (1)"
    "                     when (pEp_version_major > ?1) then (0)"
    "                     when (pEp_version_minor < ?2) then (1)"
    "                     else 0 "
    "           end) = 1 ;";

static const char *sql_set_trust =
    "insert into trust (user_id, pgp_keypair_fpr, comm_type) "
    "values (?1, upper(replace(?2,' ','')), ?3) ;";

static const char *sql_update_trust =
    "update trust set comm_type = ?3 " 
    "   where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ',''));";

static const char *sql_clear_trust_info =
    "delete from trust "
    "   where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ',''));";

static const char *sql_update_trust_to_pEp =
    "update trust set comm_type = comm_type + 71 "
    "   where (user_id = ?1 "
    "          and (case when (comm_type = 56) then (1) "
    "                    when (comm_type = 184) then (1) "
    "                    else 0"
    "               end) = 1); ";

static const char* sql_exists_trust_entry = 
    "select count(*) from trust "
    "   where user_id = ?1 and pgp_keypair_fpr = upper(replace(?2,' ',''));";
    
static const char *sql_update_trust_for_fpr =
    "update trust "
    "set comm_type = ?1 "
    "where pgp_keypair_fpr = upper(replace(?2,' ','')) ;";

static const char *sql_get_trust = 
    "select comm_type from trust where user_id = ?1 "
    "and pgp_keypair_fpr = upper(replace(?2,' ','')) ;";

static const char *sql_get_trust_by_userid = 
    "select pgp_keypair_fpr, comm_type from trust where user_id = ?1 ";

static const char *sql_least_trust = 
    "select min(comm_type) from trust where"
    " pgp_keypair_fpr = upper(replace(?1,' ',''))"
    " and comm_type != 0;"; // ignores PEP_ct_unknown
    // returns PEP_ct_unknown only when no known trust is recorded

static const char *sql_mark_as_compromised = 
    "update trust not indexed set comm_type = 15"
    " where pgp_keypair_fpr = upper(replace(?1,' ','')) ;";
    
static const char *sql_crashdump = 
    "select timestamp, title, entity, description, comment"
    " from log order by timestamp desc limit ?1 ;";

static const char *sql_languagelist = 
    "select i18n_language.lang, name, phrase" 
    " from i18n_language join i18n_token using (lang) where i18n_token.id = 1000;" ;

static const char *sql_i18n_token = 
    "select phrase from i18n_token where lang = lower(?1) and id = ?2 ;";
    
// blacklist
static const char *sql_blacklist_add = 
    "insert or ignore into blacklist_keys (fpr) values (upper(replace(?1,' ',''))) ;"
    "delete from identity where main_key_id = upper(replace(?1,' ','')) ;"
    "delete from pgp_keypair where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_blacklist_delete =
    "delete from blacklist_keys where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_blacklist_is_listed = 
    "select count(*) from blacklist_keys where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_blacklist_retrieve = 
    "select * from blacklist_keys ;";
                

// Own keys
// We only care if it's 0 or non-zero
static const char *sql_own_key_is_listed = 
    "select count(*) from ("
    "   select pgp_keypair_fpr from trust"
    "      join identity on trust.user_id = identity.user_id"
    "      where pgp_keypair_fpr = upper(replace(?1,' ',''))"
    "           and identity.is_own = 1"
    ");";
    
static const char *sql_is_own_address =
    "select count(*) from ("
    "   select address from identity"
    "       where normalize_address (?1) = normalize_address (address) "
    "           and identity.is_own = 1"
    ");";

static const char *sql_own_identities_retrieve =  
    "select address, identity.main_key_id, identity.user_id, username,"
    "   lang, identity.flags | pgp_keypair.flags, pEp_version_major, pEp_version_minor"
    "   from identity"
    "   join person on id = identity.user_id"
    "   left join pgp_keypair on fpr = identity.main_key_id"
    "   left join trust on id = trust.user_id"
    "       and pgp_keypair_fpr = identity.main_key_id"
    "   where identity.is_own = 1"
    "       and (identity.flags & ?1) = 0;";

static const char *sql_own_keys_retrieve = 
    "select distinct pgp_keypair_fpr from trust"
    "   join identity on trust.user_id = identity.user_id"
    "   where identity.is_own = 1";

static const char* sql_get_user_default_key =
    "select main_key_id from person" 
    "   where id = ?1;";

static const char* sql_get_all_keys_for_user =
    "select pgp_keypair_fpr from trust"
    "   where user_id = ?1; ";

static const char* sql_get_all_keys_for_identity = /* ?1: address; ?2: user_id */
    "SELECT T.pgp_keypair_fpr "
    "  FROM Trust T "
    "  WHERE T.user_id = ?2 "
    "UNION "
    "SELECT P.main_key_id "
    "  FROM Person P "
    "  WHERE P.id = ?2 "
    "UNION "
    "SELECT I.main_key_id "
    "  FROM Identity I "
    "  WHERE I.address = ?1 AND I.user_id = ?2 ";

static const char* sql_get_default_own_userid =
    "select id from person"
    "   join identity on id = identity.user_id"
    "   where identity.is_own = 1";
    
// Sequence
static const char *sql_sequence_value1 = 
    "insert or replace into sequences (name, value) "
    "values (?1, "
    "       (select coalesce((select value + 1 from sequences "
    "           where name = ?1), 1 ))); ";

static const char *sql_sequence_value2 = 
    "select value from sequences where name = ?1 ;";

// Revocation tracking
static const char *sql_set_revoked =
    "insert or replace into revoked_keys ("
    "    revoked_fpr, replacement_fpr, revocation_date) "
    "values (upper(replace(?1,' ','')),"
    "        upper(replace(?2,' ','')),"
    "        ?3) ;";
        
static const char *sql_get_revoked = 
    "select revoked_fpr, revocation_date from revoked_keys"
    "    where replacement_fpr = upper(replace(?1,' ','')) ;";

static const char *sql_get_replacement_fpr = 
    "select replacement_fpr, revocation_date from revoked_keys"
    "    where revoked_fpr = upper(replace(?1,' ','')) ;";

static const char *sql_get_userid_alias_default =
    "select default_id from alternate_user_id "
    "   where alternate_id = ?1 ; ";

// Revocation tracking
static const char *sql_add_mistrusted_key =
    "insert or replace into mistrusted_keys (fpr) "
    "   values (upper(replace(?1,' ',''))) ;";
        
static const char *sql_delete_mistrusted_key = 
    "delete from mistrusted_keys where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_is_mistrusted_key = 
    "select count(*) from mistrusted_keys where fpr = upper(replace(?1,' ','')) ;";

static const char *sql_add_userid_alias =
    "insert or replace into alternate_user_id (alternate_id, default_id) "
    "values (?2, ?1) ;";

static const char *sql_add_into_social_graph =
    "insert or replace into social_graph(own_userid, own_address, contact_userid) "
    "values (?1, ?2, ?3) ;";

static const char *sql_get_own_address_binding_from_contact =
    "select own_address from social_graph where own_userid = ?1 and contact_userid = ?2 ;";

static const char *sql_set_revoke_contact_as_notified =
    "insert or replace into revocation_contact_list(fpr, own_address, contact_id) values (?1, ?2, ?3) ;";
    
static const char *sql_get_contacted_ids_from_revoke_fpr =
    "select * from revocation_contact_list where fpr = ?1 ;";

static const char *sql_was_id_for_revoke_contacted = 
    "select count(*) from revocation_contact_list where fpr = ?1 and own_address = ?2 and contact_id = ?3 ;";

static const char *sql_has_id_contacted_address =
    "select count(*) from social_graph where own_address = ?1 and contact_userid = ?2 ;";

// We only need user_id and address, since in the main usage, we'll call update_identity
// on this anyway when sending out messages.
static const char *sql_get_last_contacted =
    "select user_id, address from identity where datetime('now') < datetime(timestamp, '+14 days') ; ";
        
static int user_version(void *_version, int count, char **text, char **name)
{
    if (!(_version && count == 1 && text && text[0]))
        return -1;

    int *version = (int *) _version;
    *version = atoi(text[0]);
    return 0;
}

// TODO: refactor and generalise these two functions if possible.
static int db_contains_table(PEP_SESSION session, const char* table_name) {
    if (!session || !table_name)
        return -1;
    
    // Table names can't be SQL parameters, so we do it this way.
    
    // these two must be the same number.
    char sql_buf[500];
    const size_t max_q_len = 500;
    
    size_t t_size, q_size;
    
    const char* q1 = "SELECT name FROM sqlite_master WHERE type='table' AND name='{"; // 61
    const char* q2 = "}';";       // 3
    
    q_size = 64;
    t_size = strlen(table_name);
    
    size_t query_len = q_size + t_size + 1;

    if (query_len > max_q_len)
        return -1;

    strlcpy(sql_buf, q1, max_q_len);
    strlcat(sql_buf, table_name, max_q_len);
    strlcat(sql_buf, q2, max_q_len);

    sqlite3_stmt *stmt; 

    sqlite3_prepare_v2(session->db, sql_buf, -1, &stmt, NULL);

    int retval = 0;

    int rc = sqlite3_step(stmt);  
    if (rc == SQLITE_DONE || rc == SQLITE_OK || rc == SQLITE_ROW) {
        retval = 1;
    }

    sqlite3_finalize(stmt);      
        
    return retval;
        
}

static int table_contains_column(PEP_SESSION session, const char* table_name,
                                                      const char* col_name) {


    if (!session || !table_name || !col_name)
        return -1;
        
    // Table names can't be SQL parameters, so we do it this way.
    
    // these two must be the same number.
    char sql_buf[500];
    const size_t max_q_len = 500;
    
    size_t t_size, c_size, q_size;
    
    const char* q1 = "SELECT "; // 7
    const char* q2 = " from "; // 6
    const char* q3 = ";";       // 1
    
    q_size = 14;
    t_size = strlen(table_name);
    c_size = strlen(col_name);
    
    size_t query_len = q_size + c_size + t_size + 1;
    
    if (query_len > max_q_len)
        return -1;

    strlcpy(sql_buf, q1, max_q_len);
    strlcat(sql_buf, col_name, max_q_len);
    strlcat(sql_buf, q2, max_q_len);
    strlcat(sql_buf, table_name, max_q_len);
    strlcat(sql_buf, q3, max_q_len);

    sqlite3_stmt *stmt; 

    sqlite3_prepare_v2(session->db, sql_buf, -1, &stmt, NULL);

    int retval = 0;

    int rc = sqlite3_step(stmt);  
    if (rc == SQLITE_DONE || rc == SQLITE_OK || rc == SQLITE_ROW) {
        retval = 1;
    }

    sqlite3_finalize(stmt);      
        
    return retval;
}

#define _PEP_MAX_AFFECTED 5
PEP_STATUS repair_altered_tables(PEP_SESSION session) {
    PEP_STATUS status = PEP_STATUS_OK;

    char* table_names[_PEP_MAX_AFFECTED] = {0};

    const char* sql_query = "select tbl_name from sqlite_master WHERE sql LIKE '%REFERENCES%' AND sql LIKE '%_old%';";
    sqlite3_stmt *stmt; 
    sqlite3_prepare_v2(session->db, sql_query, -1, &stmt, NULL);
    int i = 0;
    int int_result = 0;
    while ((int_result = sqlite3_step(stmt)) == SQLITE_ROW && i < _PEP_MAX_AFFECTED) {
        table_names[i++] = strdup((const char*)(sqlite3_column_text(stmt, 0)));
    }
    
    sqlite3_finalize(stmt);      

    if ((int_result != SQLITE_DONE && int_result != SQLITE_OK) || i > (_PEP_MAX_AFFECTED + 1)) {
        status = PEP_UNKNOWN_DB_ERROR;
        goto pEp_free;
    }
        
    for (i = 0; i < _PEP_MAX_AFFECTED; i++) {
        const char* table_name = table_names[i];
        if (!table_name)
            break;
            
        if (strcmp(table_name, "identity") == 0) {
            int_result = sqlite3_exec(session->db,
                "PRAGMA foreign_keys=off;\n"
                "BEGIN TRANSACTION;\n"
                "create table _identity_new (\n"
                "   address text,\n"
                "   user_id text\n"
                "       references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "   main_key_id text\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete set null,\n"
                "   comment text,\n"
                "   flags integer default 0,\n"
                "   is_own integer default 0,\n"
                "   timestamp integer default (datetime('now')),\n"
                "   primary key (address, user_id)\n"
                ");\n"
                "INSERT INTO _identity_new SELECT * from identity;\n"
                "DROP TABLE identity;\n"
                "ALTER TABLE _identity_new RENAME TO identity;\n"
                "COMMIT;\n"
                "PRAGMA foreign_keys=on;"
                ,
                NULL,
                NULL,
                NULL
            );
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "trust") == 0) {
            int_result = sqlite3_exec(session->db,
                "PRAGMA foreign_keys=off;\n"
                "BEGIN TRANSACTION;\n"
                "create table _trust_new (\n"
                "   user_id text not null\n"
                "       references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "   pgp_keypair_fpr text not null\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete cascade,\n"
                "   comm_type integer not null,\n"
                "   comment text,\n"
                "   primary key (user_id, pgp_keypair_fpr)\n"                
                ");\n"
                "INSERT INTO _trust_new SELECT * from trust;\n"
                "DROP TABLE trust;\n"
                "ALTER TABLE _trust_new RENAME TO trust;\n"
                "COMMIT;\n"
                "PRAGMA foreign_keys=on;"
                ,
                NULL,
                NULL,
                NULL
            );
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "alternate_user_id") == 0) {
            int_result = sqlite3_exec(session->db,
                "PRAGMA foreign_keys=off;\n"
                "BEGIN TRANSACTION;\n"
                "create table _alternate_user_id_new (\n"
                "    default_id text references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "    alternate_id text primary key\n"
                ");\n"
                "INSERT INTO _alternate_user_id_new SELECT * from alternate_user_id;\n"
                "DROP TABLE alternate_user_id;\n"
                "ALTER TABLE _alternate_user_id_new RENAME TO alternate_user_id;\n"
                "COMMIT;\n"
                "PRAGMA foreign_keys=on;"                
                ,
                NULL,
                NULL,
                NULL
            );
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "revocation_contact_list") == 0) {
            int_result = sqlite3_exec(session->db,
                "PRAGMA foreign_keys=off;\n"
                "BEGIN TRANSACTION;\n"
                "create table _revocation_contact_list_new (\n"
                "   fpr text not null references pgp_keypair (fpr)\n"
                "       on delete cascade,\n"
                "   contact_id text not null references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "   timestamp integer default (datetime('now')),\n"
                "   PRIMARY KEY(fpr, contact_id)\n"            
                ");\n"
                "INSERT INTO _revocation_contact_list_new SELECT * from revocation_contact_list;\n"
                "DROP TABLE revocation_contact_list;\n"
                "ALTER TABLE _revocation_contact_list_new RENAME TO revocation_contact_list;\n"
                "COMMIT;\n"
                "PRAGMA foreign_keys=on;"                
                ,
                NULL,
                NULL,
                NULL
            );
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }
        else if (strcmp(table_name, "social_graph")) {
            int_result = sqlite3_exec(session->db,
                "PRAGMA foreign_keys=off;\n"
                "BEGIN TRANSACTION;\n"
                "create table _social_new (\n"
                "    own_userid text,\n"
                "    own_address text,\n"
                "    contact_userid text,\n"
                "    CONSTRAINT fk_own_identity\n"
                "       FOREIGN KEY(own_address, own_userid)\n" 
                "       REFERENCES identity(address, user_id)\n"
                "       ON DELETE CASCADE ON UPDATE CASCADE\n"
                ");\n"
                "INSERT INTO _social_graph_new SELECT * from social_graph;\n"
                "DROP TABLE social_graph;\n"
                "ALTER TABLE _social_graph_new RENAME TO social_graph;\n"
                "COMMIT;\n"
                "PRAGMA foreign_keys=on;"                
                ,
                NULL,
                NULL,
                NULL
            );
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;
        }        
    }
    
    int_result = sqlite3_exec(
        session->db,
        "PRAGMA foreign_key_check;\n"
        ,
        NULL,
        NULL,
        NULL
    );
    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

pEp_free:
    for (i = 0; i < _PEP_MAX_AFFECTED; i++) {
        free(table_names[i]);
    }
    return status;
}
void errorLogCallback(void *pArg, int iErrCode, const char *zMsg){
  fprintf(stderr, "(%d) %s\n", iErrCode, zMsg);
}

static PEP_STATUS upgrade_revoc_contact_to_13(PEP_SESSION session) {
    // I HATE SQLITE.
    PEP_STATUS status = PEP_STATUS_OK;
    int int_result = 0;

    // Ok, first we ADD the column so we can USE it.
    // We will end up propagating the "error" this first time 
    // (one-to-one revoke-replace relationships), but since key reset
    // hasn't been used in production, this is not a customer-facing 
    // issue.
    
    // Note: the check upfront is to deal with partially-upgraded DB issues
    if (!table_contains_column(session, "revocation_contact_list", "own_address")) {
        int_result = sqlite3_exec(
            session->db,
            "alter table revocation_contact_list\n"
            "   add column own_address text;\n",
            NULL,
            NULL,
            NULL
        );
        assert(int_result == SQLITE_OK);

        if (int_result != SQLITE_OK)
            return PEP_UNKNOWN_DB_ERROR;

    }    
                
    // the best we can do here is search per address, since these
    // are no longer associated with an identity. For now, if we find 
    // something we can't add an address to, we'll delete the record.
    // this should not, in the current environment, ever happen, but 
    // since we need to make the address part of the primary key, it's 
    // the right thing to do. sqlite does support null fields in a primary 
    // key for a weird version compatibility reason, but that doesn't 
    // mean we should use it, and we should be *safe*, not relying 
    // on an implementation-specific quirk which might be sanely removed 
    // in a future sqlite version.
    
    identity_list* id_list = NULL;

    sqlite3_stmt* tmp_own_id_retrieve = NULL;
    sqlite3_prepare_v2(session->db, sql_own_identities_retrieve, -1, &tmp_own_id_retrieve, NULL);
    
    // Kludgey - put the stmt in temporarily, and then remove again, so less code dup.
    // FIXME LATER: refactor if possible, but... chicken and egg, and thiis case rarely happens.
    session->own_identities_retrieve = tmp_own_id_retrieve;
    status = own_identities_retrieve(session, &id_list);
    sqlite3_finalize(tmp_own_id_retrieve);
    session->own_identities_retrieve = NULL;

    if (!status || !id_list)
        return PEP_STATUS_OK; // it's empty AFAIK (FIXME)
    
    identity_list* curr_own = id_list;

    sqlite3_stmt* update_revoked_w_addr_stmt = NULL;
    const char* sql_query = "update revocation_contact_list set own_address = ?1 where fpr = ?2;";
    sqlite3_prepare_v2(session->db, sql_query, -1, &update_revoked_w_addr_stmt, NULL);
    
    // Ok, go through and find any keys associated with this address  
    for ( ; curr_own && curr_own->ident; curr_own = curr_own->next) {
        if (EMPTYSTR(curr_own->ident->address)) // shouldn't happen
            continue;
        stringlist_t* keylist = NULL;
        status = find_keys(session, curr_own->ident->address, &keylist);
        stringlist_t* curr_key = keylist;
        for ( ; curr_key && curr_key->value; curr_key = curr_key->next) {
            if (EMPTYSTR(curr_key->value))
                continue;
                
            // We just do this lazily - if this isn't a revoked key, it 
            // won't do anything.
            sqlite3_bind_text(update_revoked_w_addr_stmt, 1, curr_own->ident->address, -1,
                              SQLITE_STATIC);
            sqlite3_bind_text(update_revoked_w_addr_stmt, 2, curr_key->value, -1,
                              SQLITE_STATIC);
                              
            int_result = sqlite3_step(update_revoked_w_addr_stmt);
            assert(int_result == SQLITE_DONE);

            reset_and_clear_bindings(update_revoked_w_addr_stmt);

            if (int_result != SQLITE_DONE)
                return PEP_UNKNOWN_DB_ERROR;

        }
    }  
    sqlite3_finalize(update_revoked_w_addr_stmt);
                    
    int_result = sqlite3_exec(
        session->db,
        "delete from revocation_contact_list where own_address is NULL;\n"        
        "PRAGMA foreign_keys=off;\n"
        "BEGIN TRANSACTION;\n"
        "create table if not exists _revocation_contact_list_new (\n"
        "   fpr text not null references pgp_keypair (fpr)\n"
        "       on delete cascade,\n"
        "   own_address text,\n"
        "   contact_id text not null references person (id)\n"
        "       on delete cascade on update cascade,\n"
        "   timestamp integer default (datetime('now')),\n"
        "   PRIMARY KEY(fpr, own_address, contact_id)\n"
        ");\n"
        "INSERT INTO _revocation_contact_list_new (fpr, "
        "                                          own_address, "
        "                                          contact_id) "
        "   SELECT revocation_contact_list.fpr, "
        "          revocation_contact_list.own_address, "
        "          revocation_contact_list.contact_id "
        "   FROM revocation_contact_list "
        "   WHERE 1;\n"
        "DROP TABLE revocation_contact_list;\n"
        "ALTER TABLE _revocation_contact_list_new RENAME TO revocation_contact_list;\n"
        "COMMIT;\n"
        "\n"
        "PRAGMA foreign_keys=on;\n"
        ,
        NULL,
        NULL,
        NULL
    );


    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    return status;
}

DYNAMIC_API PEP_STATUS init(
        PEP_SESSION *session,
        messageToSend_t messageToSend,
        inject_sync_event_t inject_sync_event,
        ensure_passphrase_t ensure_passphrase
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int int_result;
    
    bool in_first = false;
    bool very_first = false;

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
    
    assert(LOCAL_DB);
    if (LOCAL_DB == NULL) {
        status = PEP_INIT_CANNOT_OPEN_DB;
        goto pEp_error;
    }
    
#ifdef _PEP_SQLITE_DEBUG    
    sqlite3_config(SQLITE_CONFIG_LOG, errorLogCallback, NULL);
#endif

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
        goto pEp_error;
    }

    /* Initialise our SQL extension. */
    status = _initialize_sql_extension (_session->db);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    int_result = sqlite3_exec(
            _session->db,
            "PRAGMA locking_mode=NORMAL;\n"
            "PRAGMA journal_mode=WAL;\n",
            NULL,
            NULL,
            NULL
        );


    sqlite3_busy_timeout(_session->db, BUSY_WAIT_TIME);

#ifdef _PEP_SQLITE_DEBUG
    sqlite3_trace_v2(_session->db, 
        SQLITE_TRACE_STMT | SQLITE_TRACE_ROW | SQLITE_TRACE_CLOSE,
        sql_trace_callback,
        NULL);
#endif

    assert(SYSTEM_DB);
    if (SYSTEM_DB == NULL) {
        status = PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
        goto pEp_error;
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
        goto pEp_error;
    }

    sqlite3_busy_timeout(_session->system_db, 1000);

// increment this when patching DDL
#define _DDL_USER_VERSION "14"

    if (in_first) {

        int_result = sqlite3_exec(
            _session->db,
                "create table if not exists version_info (\n"
                "   id integer primary key,\n"
                "   timestamp integer default (datetime('now')),\n"
                "   version text,\n"
                "   comment text\n"
                ");\n",
                NULL,
                NULL,
                NULL
        );
        int_result = sqlite3_exec(
            _session->db,
                "PRAGMA application_id = 0x23423423;\n"
                "create table if not exists log (\n"
                "   timestamp integer default (datetime('now')),\n"
                "   title text not null,\n"
                "   description text,\n"
                "   entity text not null,\n"
                "   comment text\n"
                ");\n"
                "create index if not exists log_timestamp on log (\n"
                "   timestamp\n"
                ");\n"
                "create table if not exists pgp_keypair (\n"
                "   fpr text primary key,\n"
                "   created integer,\n"
                "   expires integer,\n"
                "   comment text,\n"
                "   flags integer default 0\n"
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
                "   comment text,\n"
//                "   device_group text,\n"
                "   is_pEp_user integer default 0\n"
                ");\n"
                "create table if not exists identity (\n"
                "   address text,\n"
                "   user_id text\n"
                "       references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "   main_key_id text\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete set null,\n"
                "   comment text,\n"
                "   flags integer default 0,\n"
                "   is_own integer default 0,\n"
                "   pEp_version_major integer default 0,\n"
                "   pEp_version_minor integer default 0,\n"
                "   enc_format integer default 0,\n"               
                "   timestamp integer default (datetime('now')),\n"
                "   primary key (address, user_id)\n"
                ");\n"
                "create index if not exists identity_userid_addr on identity(address, user_id);\n"
                "create table if not exists trust (\n"
                "   user_id text not null\n"
                "       references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "   pgp_keypair_fpr text not null\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete cascade,\n"
                "   comm_type integer not null,\n"
                "   comment text,\n"
                "   primary key (user_id, pgp_keypair_fpr)\n"
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
                "create table if not exists revoked_keys (\n"
                "   revoked_fpr text primary key,\n"
                "   replacement_fpr text not null\n"
                "       references pgp_keypair (fpr)\n"
                "       on delete cascade,\n"
                "   revocation_date integer\n"
                ");\n"
                // user id aliases
                "create table if not exists alternate_user_id (\n"
                "    default_id text references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "    alternate_id text primary key\n"
                ");\n"
                // mistrusted keys
                "create table if not exists mistrusted_keys (\n"
                "    fpr text primary key\n"
                ");\n"
                // social graph for key resets
                "create table if not exists social_graph (\n"
                "    own_userid text,\n"
                "    own_address text,\n"
                "    contact_userid text,\n"
                "    CONSTRAINT fk_own_identity\n"
                "       FOREIGN KEY(own_address, own_userid)\n" 
                "       REFERENCES identity(address, user_id)\n"
                "       ON DELETE CASCADE ON UPDATE CASCADE\n"
                ");\n"
                // list of user_ids sent revocation
                "create table if not exists revocation_contact_list (\n"
                "   fpr text not null references pgp_keypair (fpr)\n"
                "       on delete cascade,\n"
                "   own_address text,\n"
                "   contact_id text not null references person (id)\n"
                "       on delete cascade on update cascade,\n"
                "   timestamp integer default (datetime('now')),\n"
                "   PRIMARY KEY(fpr, own_address, contact_id)\n"
                ");\n"
                ,
            NULL,
            NULL,
            NULL
        );
        assert(int_result == SQLITE_OK);

        if (int_result != SQLITE_OK)
            return PEP_UNKNOWN_DB_ERROR;


        int version;
        int_result = sqlite3_exec(
            _session->db,
            "pragma user_version;",
            user_version,
            &version,
            NULL
        );

        assert(int_result == SQLITE_OK);
        if (int_result != SQLITE_OK)
            return PEP_UNKNOWN_DB_ERROR;


        void (*xFunc_lower)(sqlite3_context*,int,sqlite3_value**) = &_sql_lower;
        
        int_result = sqlite3_create_function_v2(
            _session->db,
            "lower",
            1,
            SQLITE_UTF8 | SQLITE_DETERMINISTIC,
            NULL,
            xFunc_lower,
            NULL,
            NULL,
            NULL);

        assert(int_result == SQLITE_OK);

        if (int_result != SQLITE_OK)
            return PEP_UNKNOWN_DB_ERROR;


        int_result = sqlite3_exec(
            _session->db,
            "pragma foreign_keys=ON;\n",
            NULL,
            NULL,
            NULL
        );

        assert(int_result == SQLITE_OK);

        if (int_result != SQLITE_OK)
            return PEP_UNKNOWN_DB_ERROR;

        if (version > atoi(_DDL_USER_VERSION)) {
            // This is *explicitly* not allowed.
            return PEP_INIT_DB_DOWNGRADE_VIOLATION;
        }
        
        // Sometimes the user_version wasn't set correctly. 
        if (version == 1) {
            bool version_changed = true;
            if (table_contains_column(_session, "identity", "enc_format")) {
                version = 14;
            }
            else if (table_contains_column(_session, "revocation_contact_list", "own_address")) {
                version = 13;
            }
            else if (table_contains_column(_session, "identity", "pEp_version_major")) {
                version = 12;
            }
            else if (db_contains_table(_session, "social_graph") > 0) {
                if (!table_contains_column(_session, "person", "device_group"))
                    version = 10;
                else
                    version = 9;
            }            
            else if (table_contains_column(_session, "identity", "timestamp") > 0) {
                version = 8;
            }            
            else if (table_contains_column(_session, "person", "is_pEp_user") > 0) {
                version = 7;
            }            
            else if (table_contains_column(_session, "identity", "is_own") > 0) {
                version = 6;
            }
            else if (table_contains_column(_session, "pgp_keypair", "flags") > 0) {
                version = 2;
            }
            else {
                version_changed = false;
            }
            
            if (version_changed) {
                // set it in the DB, finally. Yeesh.
                char verbuf[21]; // enough digits for a max-sized 64 bit int, cmon. 
                sprintf(verbuf,"%d",version);
                
                size_t query_size = strlen(verbuf) + 25;
                char* query = calloc(query_size, 1);
                
                strlcpy(query, "pragma user_version = ", query_size);
                strlcat(query, verbuf, query_size);
                strlcat(query, ";", query_size);
                
                int_result = sqlite3_exec(
                    _session->db,
                    query,
                    user_version,
                    &version,
                    NULL
                );
                free(query);
            }
        }


        if(version != 0) { 
            // Version has been already set

            // Early mistake : version 0 shouldn't have existed.
            // Numbering should have started at 1 to detect newly created DB.
            // Version 0 DBs are not anymore compatible.

            // // Was version 0 compat code.
            // if (version < 1) {
            //     int_result = sqlite3_exec(
            //         _session->db,
            //         "alter table identity\n"
            //         "   add column flags integer default 0;\n",
            //         NULL,
            //         NULL,
            //         NULL
            //     );
            //     assert(int_result == SQLITE_OK);
            // }
            
            if (version < 2) {
                // N.B. addition of device_group column removed in DDL v10
                int_result = sqlite3_exec(
                    _session->db,
                    "alter table pgp_keypair\n"
                    "   add column flags integer default 0;\n",
                    // "alter table person\n"
                    // "   add column device_group text;\n",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

            }

            if (version < 5) {
                int_result = sqlite3_exec(
                    _session->db,
                    "delete from pgp_keypair where fpr = '';",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                int_result = sqlite3_exec(
                    _session->db,
                    "delete from trust where pgp_keypair_fpr = '';",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

            }
            
            if (version < 6) {
                int_result = sqlite3_exec(
                    _session->db,
                    "alter table identity\n"
                    "   add column is_own integer default 0;\n",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                int_result = sqlite3_exec(
                    _session->db,
                    "update identity\n"
                    "   set is_own = 1\n"
                    "   where (user_id = '" PEP_OWN_USERID "');\n",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;


                // Turns out that just adding "on update cascade" in
                // sqlite is a PITA. We need to be able to cascade
                // person->id replacements (for temp ids like "TOFU_")
                // so here we go...
                int_result = sqlite3_exec(
                    _session->db,
                    "PRAGMA foreign_keys=off;\n"
                    "BEGIN TRANSACTION;\n"
                    "create table _identity_new (\n"
                    "   address text,\n"
                    "   user_id text\n"
                    "       references person (id)\n"
                    "       on delete cascade on update cascade,\n"
                    "   main_key_id text\n"
                    "       references pgp_keypair (fpr)\n"
                    "       on delete set null,\n"
                    "   comment text,\n"
                    "   flags integer default 0,\n"
                    "   is_own integer default 0,\n"
                    "   primary key (address, user_id)\n"
                    ");\n"                    
                    "INSERT INTO _identity_new SELECT * FROM identity;\n"
                    "DROP TABLE identity;\n"
                    "ALTER TABLE _identity_new RENAME TO identity;\n"
                    "COMMIT;\n"
                    "\n"
                    "BEGIN TRANSACTION;\n"
                    "create table _trust_new (\n"
                    "   user_id text not null\n"
                    "       references person (id)\n"
                    "       on delete cascade on update cascade,\n"
                    "   pgp_keypair_fpr text not null\n"
                    "       references pgp_keypair (fpr)\n"
                    "       on delete cascade,\n"
                    "   comm_type integer not null,\n"
                    "   comment text,\n"
                    "   primary key (user_id, pgp_keypair_fpr)\n"
                    ");\n"
                    "INSERT INTO _trust_new SELECT * FROM trust;\n"
                    "DROP TABLE trust;\n"
                    "ALTER TABLE _trust_new RENAME TO trust;\n"
                    "COMMIT;\n"
                    "\n"
                    "PRAGMA foreign_keys=on;\n"
                    "create table if not exists alternate_user_id (\n"
                    "    default_id text references person (id)\n"
                    "       on delete cascade on update cascade,\n"
                    "    alternate_id text primary key\n"
                    ");\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                
                int_result = sqlite3_exec(
                    _session->db,
                    "PRAGMA foreign_key_check;\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;


                // FIXME: foreign key check here 
            }
            if (version < 7) {
                int_result = sqlite3_exec(
                    _session->db,
                    "alter table person\n"
                    "   add column is_pEp_user integer default 0;\n",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                int_result = sqlite3_exec(
                    _session->db,
                    "update person\n"
                    "   set is_pEp_user = 1\n"
                    "   where id = "
                    "       (select distinct id from person "
                    "               join trust on id = user_id "
                    "               where (case when (comm_type = 127) then (id) "
                    "                           when (comm_type = 255) then (id) "
                    "                           else 0"
                    "                      end) = id );\n",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                
                int_result = sqlite3_exec(
                    _session->db,
                    "create table if not exists mistrusted_keys (\n"
                    "    fpr text primary key\n"
                    ");\n",            
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

            }
            if (version < 8) {
                int_result = sqlite3_exec(
                    _session->db,
                    "PRAGMA foreign_keys=off;\n"
                    "BEGIN TRANSACTION;\n"
                    "create table _identity_new (\n"
                    "   address text,\n"
                    "   user_id text\n"
                    "       references person (id)\n"
                    "       on delete cascade on update cascade,\n"
                    "   main_key_id text\n"
                    "       references pgp_keypair (fpr)\n"
                    "       on delete set null,\n"
                    "   comment text,\n"
                    "   flags integer default 0,\n"
                    "   is_own integer default 0,\n"
                    "   timestamp integer default (datetime('now')),\n"
                    "   primary key (address, user_id)\n"
                    ");\n"
                    "INSERT INTO _identity_new (address, user_id, main_key_id, "
                    "                      comment, flags, is_own) "
                    "   SELECT identity.address, identity.user_id, "
                    "          identity.main_key_id, identity.comment, "
                    "          identity.flags, identity.is_own "
                    "   FROM identity "
                    "   WHERE 1;\n"
                    "DROP TABLE identity;\n"
                    "ALTER TABLE _identity_new RENAME TO identity;\n"
                    "COMMIT;\n"
                    "\n"
                    "PRAGMA foreign_keys=on;\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                
                int_result = sqlite3_exec(
                    _session->db,
                    "PRAGMA foreign_key_check;\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;


                // FIXME: foreign key check
            }
            if (version < 9) {
                int_result = sqlite3_exec(
                    _session->db,
                    "create table if not exists social_graph (\n"
                    "    own_userid text,\n"
                    "    own_address text,\n"
                    "    contact_userid text,\n"
                    "    CONSTRAINT fk_own_identity\n"
                    "       FOREIGN KEY(own_address, own_userid)\n" 
                    "       REFERENCES identity(address, user_id)\n"
                    "       ON DELETE CASCADE ON UPDATE CASCADE\n"
                    ");\n"
                    "create table if not exists revocation_contact_list (\n"
                    "   fpr text not null references pgp_keypair (fpr)\n"
                    "       on delete cascade,\n"
                    "   contact_id text not null references person (id)\n"
                    "       on delete cascade on update cascade,\n"
                    "   timestamp integer default (datetime('now')),\n"
                    "   PRIMARY KEY(fpr, contact_id)\n"
                    ");\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

            }
            if (version < 10 && version > 1) {
                int_result = sqlite3_exec(
                    _session->db,
                    "PRAGMA foreign_keys=off;\n"
                    "BEGIN TRANSACTION;\n"
                    "create table _person_new (\n"
                    "   id text primary key,\n"
                    "   username text not null,\n"
                    "   main_key_id text\n"
                    "       references pgp_keypair (fpr)\n"
                    "       on delete set null,\n"
                    "   lang text,\n"
                    "   comment text,\n"
                    "   is_pEp_user integer default 0\n"
                    ");\n"
                    "INSERT INTO _person_new (id, username, main_key_id, "
                    "                    lang, comment, is_pEp_user) "
                    "   SELECT person.id, person.username, "
                    "          person.main_key_id, person.lang, "
                    "          person.comment, person.is_pEp_user "
                    "   FROM person "
                    "   WHERE 1;\n"
                    "DROP TABLE person;\n"
                    "ALTER TABLE _person_new RENAME TO person;\n"
                    "COMMIT;\n"
                    "\n"
                    "PRAGMA foreign_keys=on;\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                int_result = sqlite3_exec(
                    _session->db,
                    "PRAGMA foreign_key_check;\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

            }
            if (version < 11) {
                status = repair_altered_tables(_session);
                assert(status == PEP_STATUS_OK);
                if (status != PEP_STATUS_OK)
                    return status;
            }
            if (version < 12) {
                int_result = sqlite3_exec(
                    _session->db,
                    "create index if not exists identity_userid_addr on identity(address, user_id);\n"
                    ,
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

                
                int_result = sqlite3_exec(
                    _session->db,
                    "alter table identity\n"
                    "   add column pEp_version_major integer default 0;\n"
                    "alter table identity\n"
                    "   add column pEp_version_minor integer default 0;\n",                    
                    NULL,
                    NULL,
                    NULL
                );
                if (status != PEP_STATUS_OK)
                    return status;  
      
                int_result = sqlite3_exec(
                    _session->db,
                    "update identity\n"
                    "   set pEp_version_major = 2\n"
                    "   where exists (select * from person\n"
                    "                     where identity.user_id = person.id\n"
                    "                     and identity.is_own = 0\n"
                    "                     and person.is_pEp_user = 1);\n",
                    NULL,
                    NULL,
                    NULL
                );
                if (status != PEP_STATUS_OK)
                    return status;  
                
                // N.B. WE DEFINE PEP_VERSION - IF WE'RE AT 9-DIGIT MAJOR OR MINOR VERSIONS, ER, BAD.
                char major_buf[10];
                char minor_buf[10];
                
                // Guess we were abusing sscanf here, so we'll do it this way:
                const char* cptr = PEP_VERSION;
                size_t major_len = 0;
                size_t minor_len = 0;
                
                char* bufptr = major_buf;
                while (*cptr != '.' && *cptr != '\0') {
                    *bufptr++ = *cptr++;
                    major_len++;
                }
                *bufptr = '\0';
                bufptr = minor_buf;

                if (*cptr == '.') {
                    cptr++;
                    while (*cptr != '\0') {
                        *bufptr++ = *cptr++;
                        minor_len++;
                    }
                }
                else {
                    *bufptr++ = '0';
                }
                *bufptr = '\0';
                                    
                const char* _ver_12_startstr =                     
                    "update identity\n"
                    "    set pEp_version_major = ";
                const char* _ver_12_midstr = ",\n"
                    "        pEp_version_minor = ";
                const char* _ver_12_endstr =     
                    "\n"
                    "    where identity.is_own = 1;\n";
                    
                size_t new_stringlen = strlen(_ver_12_startstr) + major_len +
                                       strlen(_ver_12_midstr) + minor_len +
                                       strlen(_ver_12_endstr);
                                       
                char* _ver_12_stmt = calloc(new_stringlen + 1, 1);
                snprintf(_ver_12_stmt, new_stringlen + 1, "%s%s%s%s%s",
                         _ver_12_startstr, major_buf, _ver_12_midstr, minor_buf, _ver_12_endstr);
                
                int_result = sqlite3_exec(
                    _session->db,
                    _ver_12_stmt,
                    NULL,
                    NULL,
                    NULL
                );
                free(_ver_12_stmt);
                if (status != PEP_STATUS_OK)
                    return status;                      
            }
            if (version < 13) {
                status = upgrade_revoc_contact_to_13(_session);
                assert(status == PEP_STATUS_OK);
                if (status != PEP_STATUS_OK)
                    return status;
            }
            if (version < 14) {
                int_result = sqlite3_exec(
                    _session->db,
                    "alter table identity\n"
                    "   add column enc_format integer default 0;\n",
                    NULL,
                    NULL,
                    NULL
                );
                assert(int_result == SQLITE_OK);

                if (int_result != SQLITE_OK)
                    return PEP_UNKNOWN_DB_ERROR;

            }
            // Do this for everybody - this is Release_2.1 patch code, because this
            // code is located elsewhere in 3.x releases

            // Version should now be "latest" - we want to upgrade the default message
            // version to 2.1 for any pEp partner.
            int_result = sqlite3_exec(
                    _session->db,
                    "update identity\n"
                    "   set pEp_version_major = 2,\n"
                    "       pEp_version_minor = 1\n"
                    "   where exists (select * from person\n"
                    "                     where identity.user_id = person.id\n"
                    "                     and identity.is_own = 0\n"
                    "                     and identity.pEp_version_major = 2\n"
                    "                     and identity.pEp_version_minor = 0\n"
                    "                     and person.is_pEp_user = 1);\n",
                    NULL,
                    NULL,
                    NULL
            );
            assert(int_result == SQLITE_OK);
        
            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;            
                    
        }        
        else { 
            // Version from DB was 0, it means this is initial setup.
            // DB has just been created, and all tables are empty.
            very_first = true;
        }

        if (version < atoi(_DDL_USER_VERSION)) {
            int_result = sqlite3_exec(
                _session->db,
                "pragma user_version = "_DDL_USER_VERSION";\n"
                "insert or replace into version_info (id, version)"
                    "values (1, '" PEP_ENGINE_VERSION "');",
                NULL,
                NULL,
                NULL
            );
            assert(int_result == SQLITE_OK);

            if (int_result != SQLITE_OK)
                return PEP_UNKNOWN_DB_ERROR;

        }
        
        // We need to init a few globals for message id that we'd rather not
        // calculate more than once.
        _init_globals();
    }

    int_result = sqlite3_prepare_v2(_session->db, sql_log,
            (int)strlen(sql_log), &_session->log, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->system_db, sql_trustword,
            (int)strlen(sql_trustword), &_session->trustword, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_identity,
            (int)strlen(sql_get_identity), &_session->get_identity, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_identity_without_trust_check,
            (int)strlen(sql_get_identity_without_trust_check), 
            &_session->get_identity_without_trust_check, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_identities_by_address,
            (int)strlen(sql_get_identities_by_address), 
            &_session->get_identities_by_address, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_get_identities_by_userid,
            (int)strlen(sql_get_identities_by_userid), 
            &_session->get_identities_by_userid, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    int_result = sqlite3_prepare_v2(_session->db, sql_get_identities_by_main_key_id,
            (int)strlen(sql_get_identities_by_main_key_id), 
            &_session->get_identities_by_main_key_id, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    int_result = sqlite3_prepare_v2(_session->db, sql_get_default_identity_fpr,
                                    (int)strlen(sql_get_default_identity_fpr), &_session->get_default_identity_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    int_result = sqlite3_prepare_v2(_session->db, sql_set_default_identity_fpr,
                                    (int)strlen(sql_set_default_identity_fpr), &_session->set_default_identity_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;
    
    
    int_result = sqlite3_prepare_v2(_session->db, sql_get_user_default_key,
            (int)strlen(sql_get_user_default_key), &_session->get_user_default_key, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_all_keys_for_user,
            (int)strlen(sql_get_all_keys_for_user), &_session->get_all_keys_for_user, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    int_result = sqlite3_prepare_v2(_session->db, sql_get_all_keys_for_identity,
            (int)strlen(sql_get_all_keys_for_identity), &_session->get_all_keys_for_identity, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_default_own_userid,
            (int)strlen(sql_get_default_own_userid), &_session->get_default_own_userid, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_get_userid_alias_default,
            (int)strlen(sql_get_userid_alias_default), &_session->get_userid_alias_default, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_add_userid_alias,
            (int)strlen(sql_add_userid_alias), &_session->add_userid_alias, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_replace_userid,
            (int)strlen(sql_replace_userid), &_session->replace_userid, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_delete_key,
            (int)strlen(sql_delete_key), &_session->delete_key, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_replace_main_user_fpr,
            (int)strlen(sql_replace_main_user_fpr), &_session->replace_main_user_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_replace_main_user_fpr_if_equal,
            (int)strlen(sql_replace_main_user_fpr_if_equal), &_session->replace_main_user_fpr_if_equal, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_main_user_fpr,
            (int)strlen(sql_get_main_user_fpr), &_session->get_main_user_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_refresh_userid_default_key,
            (int)strlen(sql_refresh_userid_default_key), &_session->refresh_userid_default_key, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_replace_identities_fpr,
            (int)strlen(sql_replace_identities_fpr), 
            &_session->replace_identities_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_remove_fpr_as_identity_default,
            (int)strlen(sql_remove_fpr_as_identity_default), 
            &_session->remove_fpr_as_identity_default, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_remove_fpr_as_user_default,
            (int)strlen(sql_remove_fpr_as_user_default), 
            &_session->remove_fpr_as_user_default, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_set_person,
            (int)strlen(sql_set_person), &_session->set_person, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_update_person,
            (int)strlen(sql_update_person), &_session->update_person, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_delete_person,
            (int)strlen(sql_delete_person), &_session->delete_person, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_exists_person,
            (int)strlen(sql_exists_person), &_session->exists_person, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_set_as_pEp_user,
            (int)strlen(sql_set_as_pEp_user), &_session->set_as_pEp_user, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_is_pEp_user,
            (int)strlen(sql_is_pEp_user), &_session->is_pEp_user, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_add_into_social_graph,
            (int)strlen(sql_add_into_social_graph), &_session->add_into_social_graph, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, 
            sql_get_own_address_binding_from_contact,
            (int)strlen(sql_get_own_address_binding_from_contact), 
            &_session->get_own_address_binding_from_contact, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, 
            sql_set_revoke_contact_as_notified,
            (int)strlen(sql_set_revoke_contact_as_notified), 
            &_session->set_revoke_contact_as_notified, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, 
            sql_get_contacted_ids_from_revoke_fpr,
            (int)strlen(sql_get_contacted_ids_from_revoke_fpr), 
            &_session->get_contacted_ids_from_revoke_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, 
            sql_was_id_for_revoke_contacted,
            (int)strlen(sql_was_id_for_revoke_contacted), 
            &_session->was_id_for_revoke_contacted, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, 
            sql_has_id_contacted_address,
            (int)strlen(sql_has_id_contacted_address), 
            &_session->has_id_contacted_address, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, 
            sql_get_last_contacted,
            (int)strlen(sql_get_last_contacted), 
            &_session->get_last_contacted, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    int_result = sqlite3_prepare_v2(_session->db, sql_set_pgp_keypair,
            (int)strlen(sql_set_pgp_keypair), &_session->set_pgp_keypair,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_set_identity_entry,
            (int)strlen(sql_set_identity_entry), &_session->set_identity_entry, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_update_identity_entry,
            (int)strlen(sql_update_identity_entry), &_session->update_identity_entry, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_exists_identity_entry,
            (int)strlen(sql_exists_identity_entry), &_session->exists_identity_entry, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_set_identity_flags,
            (int)strlen(sql_set_identity_flags), &_session->set_identity_flags,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_unset_identity_flags,
            (int)strlen(sql_unset_identity_flags), &_session->unset_identity_flags,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_set_ident_enc_format,
            (int)strlen(sql_set_ident_enc_format), &_session->set_ident_enc_format,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

            
    int_result = sqlite3_prepare_v2(_session->db, sql_set_pEp_version,
            (int)strlen(sql_set_pEp_version), &_session->set_pEp_version,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_upgrade_pEp_version_by_user_id,
            (int)strlen(sql_upgrade_pEp_version_by_user_id), &_session->upgrade_pEp_version_by_user_id,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_clear_trust_info,
            (int)strlen(sql_clear_trust_info), &_session->clear_trust_info, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_set_trust,
            (int)strlen(sql_set_trust), &_session->set_trust, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_update_trust,
            (int)strlen(sql_update_trust), &_session->update_trust, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_update_trust_to_pEp,
            (int)strlen(sql_update_trust_to_pEp), &_session->update_trust_to_pEp, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_exists_trust_entry,
                 (int)strlen(sql_exists_trust_entry), &_session->exists_trust_entry, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_update_trust_for_fpr,
            (int)strlen(sql_update_trust_for_fpr), &_session->update_trust_for_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_trust,
            (int)strlen(sql_get_trust), &_session->get_trust, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_get_trust_by_userid,
            (int)strlen(sql_get_trust_by_userid), &_session->get_trust_by_userid, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_least_trust,
            (int)strlen(sql_least_trust), &_session->least_trust, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_mark_as_compromised,
            (int)strlen(sql_mark_as_compromised), &_session->mark_compromised,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_crashdump,
            (int)strlen(sql_crashdump), &_session->crashdump, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->system_db, sql_languagelist,
            (int)strlen(sql_languagelist), &_session->languagelist, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->system_db, sql_i18n_token,
            (int)strlen(sql_i18n_token), &_session->i18n_token, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    // blacklist

    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_add,
            (int)strlen(sql_blacklist_add), &_session->blacklist_add, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_delete,
            (int)strlen(sql_blacklist_delete), &_session->blacklist_delete,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_is_listed,
            (int)strlen(sql_blacklist_is_listed),
            &_session->blacklist_is_listed, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_blacklist_retrieve,
            (int)strlen(sql_blacklist_retrieve), &_session->blacklist_retrieve,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    // Own keys
    
    int_result = sqlite3_prepare_v2(_session->db, sql_own_key_is_listed,
            (int)strlen(sql_own_key_is_listed), &_session->own_key_is_listed,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_is_own_address,
            (int)strlen(sql_is_own_address), &_session->is_own_address,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_own_identities_retrieve,
            (int)strlen(sql_own_identities_retrieve),
            &_session->own_identities_retrieve, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

 
    int_result = sqlite3_prepare_v2(_session->db, sql_own_keys_retrieve,
            (int)strlen(sql_own_keys_retrieve),
            &_session->own_keys_retrieve, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

 
    // int_result = sqlite3_prepare_v2(_session->db, sql_set_own_key,
    //         (int)strlen(sql_set_own_key),
    //         &_session->set_own_key, NULL);
    // assert(int_result == SQLITE_OK);

 
    // Sequence

    int_result = sqlite3_prepare_v2(_session->db, sql_sequence_value1,
            (int)strlen(sql_sequence_value1), &_session->sequence_value1,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_sequence_value2,
            (int)strlen(sql_sequence_value2), &_session->sequence_value2,
            NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    // Revocation tracking
    
    int_result = sqlite3_prepare_v2(_session->db, sql_set_revoked,
            (int)strlen(sql_set_revoked), &_session->set_revoked, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_get_revoked,
            (int)strlen(sql_get_revoked), &_session->get_revoked, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
    int_result = sqlite3_prepare_v2(_session->db, sql_get_replacement_fpr,
            (int)strlen(sql_get_replacement_fpr), &_session->get_replacement_fpr, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_add_mistrusted_key,
            (int)strlen(sql_add_mistrusted_key), &_session->add_mistrusted_key, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_delete_mistrusted_key,
            (int)strlen(sql_delete_mistrusted_key), &_session->delete_mistrusted_key, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;


    int_result = sqlite3_prepare_v2(_session->db, sql_is_mistrusted_key,
            (int)strlen(sql_is_mistrusted_key), &_session->is_mistrusted_key, NULL);
    assert(int_result == SQLITE_OK);

    if (int_result != SQLITE_OK)
        return PEP_UNKNOWN_DB_ERROR;

    
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

        /**
         * ENGINE-947:
         * from the sqlite3 documentation ([https://www.sqlite.org/c3ref/finalize.html] :
         * "sqlite3-documentation: Invoking sqlite3_finalize() on a NULL pointer is a harmless no-op."
         */
        if (session->db) {
            sqlite3_finalize(session->log);
            sqlite3_finalize(session->trustword);
            sqlite3_finalize(session->get_identity);
            sqlite3_finalize(session->get_identity_without_trust_check);
            sqlite3_finalize(session->get_identities_by_address);            
            sqlite3_finalize(session->get_identities_by_userid);                
            sqlite3_finalize(session->get_identities_by_main_key_id);                                
            sqlite3_finalize(session->get_default_identity_fpr);
            sqlite3_finalize(session->set_default_identity_fpr);
            sqlite3_finalize(session->get_user_default_key);
            sqlite3_finalize(session->get_all_keys_for_user);                        
            sqlite3_finalize(session->get_default_own_userid);
            sqlite3_finalize(session->get_userid_alias_default);
            sqlite3_finalize(session->add_userid_alias);
            sqlite3_finalize(session->replace_identities_fpr);        
            sqlite3_finalize(session->remove_fpr_as_identity_default);            
            sqlite3_finalize(session->remove_fpr_as_user_default);            
            sqlite3_finalize(session->set_person);
            sqlite3_finalize(session->delete_person);                
            sqlite3_finalize(session->update_person);
            sqlite3_finalize(session->set_as_pEp_user);
            sqlite3_finalize(session->upgrade_pEp_version_by_user_id);
            sqlite3_finalize(session->is_pEp_user);
            sqlite3_finalize(session->exists_person);
            sqlite3_finalize(session->add_into_social_graph);  
            sqlite3_finalize(session->get_own_address_binding_from_contact);  
            sqlite3_finalize(session->set_revoke_contact_as_notified);  
            sqlite3_finalize(session->get_contacted_ids_from_revoke_fpr);  
            sqlite3_finalize(session->was_id_for_revoke_contacted);  
            sqlite3_finalize(session->has_id_contacted_address);
            sqlite3_finalize(session->get_last_contacted);                                       
            sqlite3_finalize(session->set_pgp_keypair);
            sqlite3_finalize(session->exists_identity_entry);                
            sqlite3_finalize(session->set_identity_entry);
            sqlite3_finalize(session->update_identity_entry);    
            sqlite3_finalize(session->set_identity_flags);
            sqlite3_finalize(session->unset_identity_flags);
            sqlite3_finalize(session->set_ident_enc_format);
            sqlite3_finalize(session->set_pEp_version);                
            sqlite3_finalize(session->exists_trust_entry);                                
            sqlite3_finalize(session->clear_trust_info);                
            sqlite3_finalize(session->set_trust);
            sqlite3_finalize(session->update_trust);
            sqlite3_finalize(session->update_trust_to_pEp);                                                
            sqlite3_finalize(session->update_trust_for_fpr);
            sqlite3_finalize(session->get_trust);
            sqlite3_finalize(session->get_trust_by_userid);                
            sqlite3_finalize(session->least_trust);
            sqlite3_finalize(session->mark_compromised);
            sqlite3_finalize(session->crashdump);
            sqlite3_finalize(session->languagelist);
            sqlite3_finalize(session->i18n_token);
            sqlite3_finalize(session->replace_userid);
            sqlite3_finalize(session->delete_key);                
            sqlite3_finalize(session->replace_main_user_fpr);                
            sqlite3_finalize(session->replace_main_user_fpr_if_equal);                                
            sqlite3_finalize(session->get_main_user_fpr);
            sqlite3_finalize(session->refresh_userid_default_key);
            sqlite3_finalize(session->blacklist_add);
            sqlite3_finalize(session->blacklist_delete);
            sqlite3_finalize(session->blacklist_is_listed);
            sqlite3_finalize(session->blacklist_retrieve);
            sqlite3_finalize(session->own_key_is_listed);
            sqlite3_finalize(session->is_own_address);
            sqlite3_finalize(session->own_identities_retrieve);
            sqlite3_finalize(session->own_keys_retrieve);
            //     sqlite3_finalize(session->set_own_key);
            sqlite3_finalize(session->sequence_value1);
            sqlite3_finalize(session->sequence_value2);
            sqlite3_finalize(session->set_revoked);
            sqlite3_finalize(session->get_revoked);
            sqlite3_finalize(session->get_replacement_fpr);                
            sqlite3_finalize(session->add_mistrusted_key);
            sqlite3_finalize(session->delete_mistrusted_key);
            sqlite3_finalize(session->is_mistrusted_key);
                
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

DYNAMIC_API void config_key_election_disabled(PEP_SESSION session, bool disable) {
    assert(session);
    if (session)
        session->key_election_disabled = disable;
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

    reset_and_clear_bindings(session->log);
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
    reset_and_clear_bindings(session->log);
    
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

    reset_and_clear_bindings(session->trustword);
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

    reset_and_clear_bindings(session->trustword);
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
    
    reset_and_clear_bindings(session->get_default_own_userid);

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

    reset_and_clear_bindings(session->get_default_own_userid);
    
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

    reset_and_clear_bindings(session->get_userid_alias_default);
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

    reset_and_clear_bindings(session->get_userid_alias_default);
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

    reset_and_clear_bindings(session->add_userid_alias);
    sqlite3_bind_text(session->add_userid_alias, 1, default_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_userid_alias, 2, alias_id, -1,
            SQLITE_STATIC);
        
    result = sqlite3_step(session->add_userid_alias);

    reset_and_clear_bindings(session->add_userid_alias);
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

    reset_and_clear_bindings(session->get_identity);
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
            reset_and_clear_bindings(session->get_identity);
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
        reset_and_clear_bindings(session->get_identity);
        status = PEP_CANNOT_FIND_IDENTITY;
        *identity = NULL;
    }

    reset_and_clear_bindings(session->get_identity);
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

    reset_and_clear_bindings(session->get_identities_by_userid);
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
            reset_and_clear_bindings(session->get_identities_by_userid);
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
            
    reset_and_clear_bindings(session->get_identities_by_userid);

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

    reset_and_clear_bindings(session->get_identities_by_main_key_id);
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
            reset_and_clear_bindings(session->get_identities_by_main_key_id);
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
            
    reset_and_clear_bindings(session->get_identities_by_main_key_id);

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

    reset_and_clear_bindings(session->get_identity_without_trust_check);
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
            reset_and_clear_bindings(session->get_identity_without_trust_check);
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

    reset_and_clear_bindings(session->get_identity_without_trust_check);
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

    reset_and_clear_bindings(session->get_identities_by_address);
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
            reset_and_clear_bindings(session->get_identities_by_address);
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

    reset_and_clear_bindings(session->get_identities_by_address);
    
    *id_list = ident_list;
    
    if (!ident_list)
        return PEP_CANNOT_FIND_IDENTITY;
    
    return PEP_STATUS_OK;
}

PEP_STATUS exists_identity_entry(PEP_SESSION session, pEp_identity* identity,
                                 bool* exists) {
    if (!session || !exists || !identity || EMPTYSTR(identity->user_id) || EMPTYSTR(identity->address))
        return PEP_ILLEGAL_VALUE;
    
    *exists = false;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    reset_and_clear_bindings(session->exists_identity_entry);
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

    reset_and_clear_bindings(session->exists_identity_entry);
    return status;
}

PEP_STATUS exists_trust_entry(PEP_SESSION session, pEp_identity* identity,
                              bool* exists) {
    if (!session || !exists || !identity || EMPTYSTR(identity->user_id) || EMPTYSTR(identity->fpr))
        return PEP_ILLEGAL_VALUE;
    
    *exists = false;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    reset_and_clear_bindings(session->exists_trust_entry);
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
    
    reset_and_clear_bindings(session->exists_trust_entry);
    return status;
}

PEP_STATUS set_pgp_keypair(PEP_SESSION session, const char* fpr) {
    if (!session || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;
        
    int result;
    
    reset_and_clear_bindings(session->set_pgp_keypair);
    sqlite3_bind_text(session->set_pgp_keypair, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->set_pgp_keypair);
    reset_and_clear_bindings(session->set_pgp_keypair);
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
    
    reset_and_clear_bindings(session->clear_trust_info);
    sqlite3_bind_text(session->clear_trust_info, 1, user_id, -1,
            SQLITE_STATIC);    
    sqlite3_bind_text(session->clear_trust_info, 2, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->clear_trust_info);
    reset_and_clear_bindings(session->clear_trust_info);
    if (result != SQLITE_DONE) {
        return PEP_UNKNOWN_ERROR;
    }
    
    return PEP_STATUS_OK;
}

static PEP_STATUS _set_or_update_trust(PEP_SESSION session,
                                       pEp_identity* identity,
                                       sqlite3_stmt* set_or_update) {
    
    if (!session || !identity || EMPTYSTR(identity->user_id) || EMPTYSTR(identity->fpr))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = set_pgp_keypair(session, identity->fpr);
    if (status != PEP_STATUS_OK)
        return status;
        
    int result;
                
    reset_and_clear_bindings(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_int(set_or_update, 3, identity->comm_type);
    result = sqlite3_step(set_or_update);
    assert(result == SQLITE_DONE);
    reset_and_clear_bindings(set_or_update);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    return PEP_STATUS_OK;
}

static PEP_STATUS _set_or_update_identity_entry(PEP_SESSION session,
                                                pEp_identity* identity,
                                                sqlite3_stmt* set_or_update) {
                      
    if (!session || !identity || !identity->user_id || !identity->address)
        return PEP_ILLEGAL_VALUE;
                                              
    reset_and_clear_bindings(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, EMPTYSTR(identity->fpr) ? NULL : identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 3, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_int(set_or_update, 4, identity->flags);
    sqlite3_bind_int(set_or_update, 5, identity->me);
    sqlite3_bind_int(set_or_update, 6, identity->major_ver);
    sqlite3_bind_int(set_or_update, 7, identity->minor_ver);
        
    int result = sqlite3_step(set_or_update);
    reset_and_clear_bindings(set_or_update);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;
    
    return PEP_STATUS_OK;
}

static PEP_STATUS _set_or_update_person(PEP_SESSION session, 
                                        pEp_identity* identity,
                                        sqlite3_stmt* set_or_update) {
                        
    if (!session || !identity || !identity->user_id || !identity->username)
        return PEP_ILLEGAL_VALUE;
        
    reset_and_clear_bindings(set_or_update);
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
    reset_and_clear_bindings(set_or_update);
    
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

PEP_STATUS _set_trust_internal(PEP_SESSION session, pEp_identity* identity,
                               bool guard_transaction) {
    return set_or_update_with_identity(session, identity,
                                       _set_or_update_trust,
                                        exists_trust_entry,
                                        session->update_trust,
                                        session->set_trust,
                                        guard_transaction);
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

PEP_STATUS set_identity_entry(PEP_SESSION session, pEp_identity* identity,
                              bool guard_transaction) {
    return set_or_update_with_identity(session, identity,
                                       _set_or_update_identity_entry,
                                       exists_identity_entry,
                                       session->update_identity_entry,
                                       session->set_identity_entry,
                                       guard_transaction);
}

// FIXME: move
void sql_begin_transaction(PEP_SESSION session)
{
    assert (session);
    if (! session)
        abort ();
    sqlite3_exec(session->db, "BEGIN_TRANSACTION;", NULL, NULL, NULL);
}

// FIXME: move
void sql_commit_transaction(PEP_SESSION session)
{
    assert (session);
    if (! session)
        abort ();
    sqlite3_exec(session->db, "COMMIT;", NULL, NULL, NULL);
}

// FIXME: move
void sql_rollback_transaction(PEP_SESSION session)
{
    assert (session);
    if (! session)
        abort ();
    sqlite3_exec(session->db, "ROLLBACK;", NULL, NULL, NULL);
}

// FIXME: possibly move definition.  statement can be NULL.
#define CHECK_SQL_RESULT(statement, result)                        \
    do {                                                           \
        int _sql_result_copy = (result);                           \
        sqlite3_stmt *_sql_statement = (statement);                \
        if (_sql_result_copy != SQLITE_OK                          \
            && _sql_result_copy != SQLITE_ROW                      \
            && _sql_result_copy != SQLITE_DONE) {                  \
            fprintf (stderr,                                       \
                     "%s:%i: (%s): SQL error: %s => %s (%i)\n",    \
                     __FILE__, __LINE__, __FUNCTION__,             \
                     ((_sql_statement == NULL)                     \
                      ? "<Unknown SQL statement>"                  \
                      : sqlite3_expanded_sql (_sql_statement)),    \
                     sqlite3_errstr (_sql_result_copy),            \
                     _sql_result_copy);                            \
            /*abort ();*/ /* FIXME: remove, of course */ \
            goto end;                                              \
        }                                                          \
    } while (false)

/* This is only used internally by set_identity.  It describes in a very
   explicit way what the present case is, when we are setting an identity from
   volatile storage to the database.
   We have to consider the cross-product of:
   - a: the volatile identity has no user_id (we only consider the address);
   - b: the volatile identity has the user_id set (we then require a match of
     both address and user_id);
   and:
   - 1: there is no matching persistent identity;
   - 2: there is a exactly one persistent temporary identity that matches
        (more than one match is impossible: invalid database state);
   - 3: there is exactly one persistent non-temporary identity that matches
        (more than one is impossible: database constraint violation);
   - 4: multiple non-temporary identities, none matching.
   Notice that the cross-product above is only reasonable for the pEp engine
   version 2.
   In v3 things are much more subtle, because there are *two* distinct username
   columns, one in Identity and another in Person, to support fake accounts.
   When porting to v3 the matrix covering every case will become larger. */
enum _set_identity_case {
    /* These are not valid cases, but they are useful to define the value of the
       actually possible cases. */
    _set_identity_case_a          = 8,
    _set_identity_case_b          = 16,
    _set_identity_case_impossible = 256, /* Engine bug or invalid database */
    _set_identity_case_1          = 1,
    _set_identity_case_2          = 2,
    _set_identity_case_3          = 3,
    _set_identity_case_4          = 4,

    _set_identity_case_a1 = _set_identity_case_a | _set_identity_case_1,
    _set_identity_case_a2 = _set_identity_case_a | _set_identity_case_2,
    _set_identity_case_a3 = _set_identity_case_a | _set_identity_case_3,
    _set_identity_case_a4 = _set_identity_case_a | _set_identity_case_4,
    _set_identity_case_b1 = _set_identity_case_b | _set_identity_case_1,
    _set_identity_case_b2 = _set_identity_case_b | _set_identity_case_2,
    _set_identity_case_b3 = _set_identity_case_b | _set_identity_case_3,
    _set_identity_case_b4 = _set_identity_case_b | _set_identity_case_4,
};

/* Return a statically-allocated string containing a printed representation
   of the given _set_identity_case. */
static const char *set_identity_case_to_string (enum _set_identity_case c)
{
    switch (c) {
    case _set_identity_case_impossible: return "IMPOSSIBLE";
    case _set_identity_case_a1:         return "a1";
    case _set_identity_case_a2:         return "a2";
    case _set_identity_case_a3:         return "a3";
    case _set_identity_case_a4:         return "a4";
    case _set_identity_case_b1:         return "b1";
    case _set_identity_case_b2:         return "b2";
    case _set_identity_case_b3:         return "b3";
    case _set_identity_case_b4:         return "b4";
    default:                            return "OTHER IMPOSSIBLE CASE";
    }
}

/* This is a helper for _find_set_identity_case, only supporting the a case. */
static enum _set_identity_case _find_set_identity_case_a(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    enum _set_identity_case res = _set_identity_case_a;
    int sql_result = SQLITE_OK;
    bool any_match;

    /* We have no user_id to check: search any entry with a matching address. */
    sqlite3_stmt *sql_statement;
    sql_result = sqlite3_prepare_v2
        (session->db,
         "SELECT user_id "
         "FROM Identity "
         "WHERE normalize_address (address) = normalize_address (?1);",
         -1,
         & sql_statement,
         NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text(sql_statement, 1, identity->address,
                                   -1, SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    any_match = (sql_result != SQLITE_DONE);
    //fprintf (stderr, "QQQ A: %i: any match: %s\n", sql_result, (any_match ? "yes":"no"));

    /* If no row matched we are in case 1... */
    if (! any_match) {
        res |= _set_identity_case_1;
        //fprintf (stderr, "QQQ 1\n");
        goto end;
    }

    /* ...Otherwise, if we are here, we are in one of the other cases 2..4. */
    bool found_a_temporary_user_id = false;
    int matching_row_no = /* We have found a row already, but we are about to
                             incrementally increment this */ 0;
    do {
        /* Handle the last row we have found. */
        matching_row_no ++;
        const unsigned char *user_id = sqlite3_column_text (sql_statement, 0);
        fprintf (stderr, "* FROM DB: <user_id: %s, address: %s>\n", user_id, identity->address);
        if (_is_temporary_user_id (user_id))
            found_a_temporary_user_id = true;

        /* Get the next row, if any. */
        sql_result = sqlite3_step(sql_statement);
        CHECK_SQL_RESULT (sql_statement, sql_result);
        //fprintf (stderr, "sql_result is %i\n", sql_result);
    } while (sql_result == SQLITE_ROW);

    /* If we found one matching temporary identity (we have checked that it is
       only one) then we know what case this is. */
    if (found_a_temporary_user_id) {
        //fprintf (stderr, "QQQ 2\n");
        res |= _set_identity_case_2;

        /* If any temporary match exists it must be the only one. */
        if (matching_row_no != 1) {
            fprintf (stderr, "Database anomaly: address %s has a temporary userid, plus at least another userid\n", identity->address);
            abort ();
/*
  FIXME: this anonmaly can be fixed at startup by a migration SQL statement
  doing
    DELETE FROM Identity WHERE EXISTS...
    DELETE FROM Trust WHERE EXISTS...
  The idea is deleting temporary addresses where a non-temporary address also
  exists.
  Then, I would add:
    for every temporary userid delete Identity rows with the
    same address but different uids
*/
        }
    }
    else if (matching_row_no == 1) {
        //fprintf (stderr, "QQQ 3\n");
        res |= _set_identity_case_3;
    }
    else {
        //fprintf (stderr, "QQQ 4\n");
        res |= _set_identity_case_4;
    }

 end:
    sqlite3_finalize(sql_statement);
    return res;
}

/* See the comment _find_set_identity_case_a. */
static enum _set_identity_case _find_set_identity_case_b(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    enum _set_identity_case res = _set_identity_case_b;
    // fprintf (stderr, "QQQ user_id \"%s\": are we in the A case? %s\n", identity->user_id, (is_a ? "YES" : "no"));
    int sql_result = SQLITE_OK;

    /* Perform an exact search, looking at user_id and address. */
    sqlite3_stmt *sql_statement;
    sql_result = sqlite3_prepare_v2
        (session->db,
         "SELECT user_id, address "
         "FROM Identity "
         "WHERE normalize_address (address) = normalize_address (?1) "
         "      AND user_id = ?2;",
         -1,
         & sql_statement,
         NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);

    sql_result = sqlite3_bind_text(sql_statement, 1, identity->address,
                                   -1, SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_text(sql_statement, 2, identity->user_id,
                                   -1, SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);

    /* If we found an exact match then this is B3... */
    bool any_match = (sql_result != SQLITE_DONE);
    if (any_match) {
        res |= _set_identity_case_3;
        goto end;
    }
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* ...Otherwise we cannot tell without another query where we search for the
       address only. */
    sql_result = sqlite3_prepare_v2
        (session->db,
         "SELECT user_id "
         "FROM Identity "
         "WHERE normalize_address (?1) = normalize_address (address);",
         -1,
         & sql_statement,
         NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text(sql_statement, 1, identity->address,
                                   -1, SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);

    /* In case of no match, this is B1. */
    any_match = (sql_result != SQLITE_DONE);
    if (! any_match) {
        fprintf (stderr, "*: we are in the B1 case that might be wrong: sql_result is %i (any_match is %i) when searching for %s using %s\n", sql_result, any_match, identity->address, sqlite3_expanded_sql (sql_statement));
        res |= _set_identity_case_1;
        goto end;
    }

    /* If the userid is temporary, the case is B2, otherwise it is B4 -- We have
       already excluded B3. */
    const unsigned char *user_id = sqlite3_column_text(sql_statement, 0);
    if (_is_temporary_user_id(user_id))
        res |= _set_identity_case_2;
    else
        res |= _set_identity_case_4;

 end:
    sqlite3_finalize(sql_statement);
    return res;
}

/* Given an identity to be used in set_identity, return the appropriate
   _set_identity_case for it.
   This is used as a helper for set_identity, which validates inputs.
   FIXME: Volker, is this acceptable or do we need to be paranoid? */
static enum _set_identity_case _find_set_identity_case(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    if (EMPTYSTR (identity->user_id))
        return _find_set_identity_case_a(session, identity);
    else
        return _find_set_identity_case_b(session, identity);
}

/* A helper function factoring the common code in _set_identity_a1 and
   _set_identity_b1, which need to insert one new line each in the Person and
   Identity tables.  This function uses the given user_id when writing into the
   database, and ignores any user_id from the identity. */
static PEP_STATUS _set_identity_insert_new(
        PEP_SESSION session, const pEp_identity *identity, const char *user_id
    )
{
    int sql_result = SQLITE_OK;
    sqlite3_stmt *sql_statement = NULL;

    /* First DML statement: Insert a new Person row. */
    sql_result = sqlite3_prepare_v2
      (session->db,
       "INSERT INTO Person "
       "  (id, username, lang, is_pEp_user) " // *not* setting the main_key_id, on purpose
       "VALUES "
       "  (?1, ?2, ?3, ?4);",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);

    sql_result = sqlite3_bind_text (sql_statement, 1, user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_text (sql_statement, 2, identity->username, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    if (EMPTYSTR (identity->lang))
        sql_result = sqlite3_bind_null (sql_statement, 3);
    else
        sql_result = sqlite3_bind_text (sql_statement, 3, identity->lang, -1,
                                        SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 4, identity->major_ver > 0);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* Second DML statement: Insert a new Identity row, referring the new Person
       row. */
    sql_result = sqlite3_prepare_v2
      (session->db,
       "INSERT INTO Identity "
       "  (address, user_id, flags, is_own, " // *not* setting main_key_id, on purpose
       "   pEp_version_major, pEp_version_minor, enc_format) "
       "VALUES "
       "  (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);

    sql_result = sqlite3_bind_text (sql_statement, 1, identity->address, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_text (sql_statement, 2, user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 3, identity->flags);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 4, identity->me);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 5, identity->major_ver);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 6, identity->minor_ver);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 7, identity->enc_format);
    CHECK_SQL_RESULT (sql_statement, sql_result);

    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);

 end:
    sqlite3_finalize(sql_statement);
    //return (sql_result == SQLITE_OK || sql_result == SQLITE_DONE) ? PEP_STATUS_OK : PEP_COMMIT_FAILED;
    return (sql_result == SQLITE_DONE) ? PEP_STATUS_OK : PEP_COMMIT_FAILED;
}

/* Just like _set_identity_insert_new, this is a helper factoring the action of
   multiple set_identity cases.  This updates an existing row in each of Person
   and Identity, using the given user_id (any user_id in identity is ignored)
   and the address in identity. */
static PEP_STATUS _set_identity_update_existing(
        PEP_SESSION session, const pEp_identity *identity, const char *user_id
    )
{
    int sql_result = SQLITE_OK;
    sqlite3_stmt *sql_statement = NULL;

    /* First DML statement: Update the Person table. */
    sql_result = sqlite3_prepare_v2
      (session->db,
       "UPDATE Person "
       "SET "
       // *not* setting id
       "    username = ?1, "
       // *not* setting main_key_id
       "    lang = ?2, "
       "    is_pEp_user = ?3 "
       "WHERE id = ?4;",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);

    sql_result = sqlite3_bind_text (sql_statement, 1, identity->username, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    if (EMPTYSTR (identity->lang))
        sql_result = sqlite3_bind_null (sql_statement, 2);
    else
        sql_result = sqlite3_bind_text (sql_statement, 2, identity->lang, -1,
                                        SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 3, identity->major_ver > 0);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_text (sql_statement, 4, user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* Second DML statement: Update the Identity table. */
    sql_result = sqlite3_prepare_v2
      (session->db,
       "UPDATE Identity "
       "SET "
       //  *not* setting address
       //  *not* setting user_id
       //  *not* setting main_key_id
       "   flags = ?1, "
       "   is_own = ?2, "
       "   pEp_version_major = ?3, "
       "   pEp_version_minor = ?4, "
       "   enc_format = ?5 "
       "WHERE user_id = ?6;",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_int (sql_statement, 1, identity->flags);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 2, identity->me);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 3, identity->major_ver);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 4, identity->minor_ver);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_int (sql_statement, 5, identity->enc_format);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_text (sql_statement, 6, user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);

 end:
    sqlite3_finalize(sql_statement);
    return (sql_result == SQLITE_DONE) ? PEP_STATUS_OK : PEP_COMMIT_FAILED;
}

/* A helper function for set_identity, implementing one of the cases in enum
   _set_identity_case; see its comment.  Arguments validated in set_identity.
   This is executed within an SQL transation, which is began and committed or
   rolled back in the caller. */
static PEP_STATUS _set_identity_a1(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* There is no user_id.  Make a new temporary one. */
    size_t user_id_size
        = /* "TOFU_" */ 5 + strlen(identity->address) + /* '\0' */ 1;
    char *user_id = calloc(1, user_id_size);
    if (user_id == NULL)
        return PEP_OUT_OF_MEMORY;
    snprintf(user_id, user_id_size, "TOFU_%s", identity->address);

    /* Use the helper _set_identity_insert_new to write a new record, and free
       the user_id before leaving. */
    PEP_STATUS res = _set_identity_insert_new (session, identity, user_id);
    free(user_id);
    return res;
}

/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_a2(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* This identity exists in the database, with a temporary userid (there is
       no userid in the volatile entry).  Leave the database userid as it is and
       set the other fields. */
    int sql_result = SQLITE_OK;
    sqlite3_stmt *sql_statement = NULL;

    /* Query: find the userid in the database. */
    char *temporary_user_id = NULL;
    sql_result = sqlite3_prepare_v2
      (session->db,
       "SELECT user_id "
       "FROM Identity "
       "WHERE normalize_address (?1) = normalize_address (address);",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text (sql_statement, 1, identity->address, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    /* This will give only one result in the A2 case but I do not want to
       verify it, since this function is also reused for the A4 case where
       results are more than one. */
    CHECK_SQL_RESULT (sql_statement, sql_result);
    temporary_user_id = strdup (sqlite3_column_text (sql_statement, 0));
    if (temporary_user_id == NULL) {
        sqlite3_finalize(sql_statement);
        return PEP_OUT_OF_MEMORY;
    }
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* Update an existing row. */
    PEP_STATUS res
        = _set_identity_update_existing (session, identity, temporary_user_id);
    free(temporary_user_id);
    return res;

 end:
    sqlite3_finalize(sql_statement);
    return PEP_COMMIT_FAILED;
}
/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_a3(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* Search for the existing userid for this address in the database... */
    PEP_STATUS res = PEP_COMMIT_FAILED;
    char *existing_user_id = NULL;
    int sql_result = SQLITE_OK;
    sqlite3_stmt *sql_statement = NULL;
    sql_result = sqlite3_prepare_v2
      (session->db,
       "SELECT user_id "
       "FROM Identity "
       "WHERE normalize_address (?1) = normalize_address (address);",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text (sql_statement, 1, identity->address, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    existing_user_id = strdup (sqlite3_column_text (sql_statement, 0));
    if (existing_user_id == NULL) {
        sqlite3_finalize(sql_statement);
        return PEP_OUT_OF_MEMORY;
    }
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* ...Then update the existing rows. */
    res = _set_identity_update_existing (session, identity, existing_user_id);

 end:
    sqlite3_finalize(sql_statement);
    free(existing_user_id);
    return res;
}
/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_a4(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* This is bizarre.  There are multiple non-temporary records for the same
       address; we have to update one, but there is no way to know which one
       is the one we want.  Choose one arbitrarily, and update that.  In fact
       this is what we do in the a2 case, except that in a2 we have the
       guarantee that the record will be only one. */
    fprintf (stderr,
             "%s: WARNING: multiple non-temporary records for the same "
             "address.  Updating *one*, chosen arbitrarily\n", __FUNCTION__);
    return _set_identity_a2(session, identity);
}
/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_b1(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* We need to create a new record.  This is very similar to the a1 case,
       except that the userid is given in identity.  The helper
       _set_identity_insert_new factors the common code. */
    return _set_identity_insert_new(session, identity, identity->user_id);
}
/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_b2(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* This is the most difficult case.  We have to conceptually change the
       primary key in the rows of several tables; but doing that would break
       foreign key constraints, so instead we have to delete and re-insert;
       the exception is Trust, where we can actually afford a rename.
       Notice that both Trust and Identity reference Person.  An appropriate
       order which does not violate constraints is therefore:
       - delete from Identity;
       - insert into Person and Identity (we have a helper function);
       - update Trust, referencing the new rows in Person;
       - delete from Person.
       Before doing this we need to find the current user_id in the database,
       which is different from the one in identity. */
    PEP_STATUS res = PEP_COMMIT_FAILED;
    int sql_result = SQLITE_OK;
    sqlite3_stmt *sql_statement = NULL;

    /* Query: find the user_id. */
    fprintf (stderr, "%s: query\n", __FUNCTION__);
    char *old_temporary_user_id = NULL;
    sql_result = sqlite3_prepare_v2
      (session->db,
       "SELECT user_id "
       "FROM Identity "
       "WHERE normalize_address (?1) = normalize_address (address);",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text (sql_statement, 1, identity->address, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    old_temporary_user_id = strdup (sqlite3_column_text (sql_statement, 0));
    if (old_temporary_user_id == NULL) {
        sqlite3_finalize(sql_statement);
        return PEP_OUT_OF_MEMORY;
    }
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* First DML statement: delete from Identity. */
    fprintf (stderr, "%s: DML1\n", __FUNCTION__);
    sql_result = sqlite3_prepare_v2
      (session->db,
       "DELETE "
       "FROM Identity "
       "WHERE normalize_address (?1) = normalize_address (address);",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text (sql_statement, 1, identity->address, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* Insert new rows into Person and Identity. */
    fprintf (stderr, "%s: Insert new rows\n", __FUNCTION__);
    if (_set_identity_insert_new(session, identity, identity->user_id)
        != PEP_STATUS_OK)
        goto end;

    /* Update Trust, referencing the new rows. */
    fprintf (stderr, "%s: DML2\n", __FUNCTION__);
    sql_result = sqlite3_prepare_v2
      (session->db,
       "UPDATE Trust "
       "SET user_id = ?1 "
       "WHERE user_id = ?2;",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text (sql_statement, 1, identity->user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_bind_text (sql_statement, 2, old_temporary_user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* Delete the old row from Person, now no longer referenced. */
    fprintf (stderr, "%s: DML3\n", __FUNCTION__);
    sql_result = sqlite3_prepare_v2
      (session->db,
       "DELETE "
       "FROM Person "
       "WHERE id = ?1;",
       -1,
       & sql_statement,
       NULL);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    reset_and_clear_bindings(sql_statement);
    sql_result = sqlite3_bind_text (sql_statement, 1, old_temporary_user_id, -1,
                                    SQLITE_STATIC);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sql_result = sqlite3_step(sql_statement);
    CHECK_SQL_RESULT (sql_statement, sql_result);
    sqlite3_finalize(sql_statement); sql_statement = NULL;

    /* If we arrived here then everything worked. */
    res = PEP_STATUS_OK;

 end:
    sqlite3_finalize(sql_statement);
    free(old_temporary_user_id);
    return res;
}
/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_b3(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* There is an exact match, so we can simply update the non-key fields. */
    return _set_identity_update_existing(session, identity, identity->user_id);
}
/* See the comment in _set_identity_a1. */
static PEP_STATUS _set_identity_b4(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    /* Insert a new record. */
    return _set_identity_insert_new(session, identity, identity->user_id);
}

DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (! session || ! identity || EMPTYSTR (identity->address)
        /* user_id may or may not be supplied. */
        || EMPTYSTR (identity->username))
        return PEP_ILLEGAL_VALUE;

    /* Open a transaction: it is inside the transaction that we want to analyse
       the set-identity case, so that we are not concerned with concurrent
       updates. */
    sql_begin_transaction (session);

    /* Find which case we are in and handle it. */
    enum _set_identity_case set_identity_case
        = _find_set_identity_case(session, identity);
    fprintf (stderr, "%s on %s: handling case %s\n", __FUNCTION__, identity->address, set_identity_case_to_string (set_identity_case));

    switch (set_identity_case) {
    case _set_identity_case_a1:
        status = _set_identity_a1 (session, identity); break;
    case _set_identity_case_a2:
        status = _set_identity_a2 (session, identity); break;
    case _set_identity_case_a3:
        status = _set_identity_a3 (session, identity); break;
    case _set_identity_case_a4:
        status = _set_identity_a4 (session, identity); break;
    case _set_identity_case_b1:
        status = _set_identity_b1 (session, identity); break;
    case _set_identity_case_b2:
        status = _set_identity_b2 (session, identity); break;
    case _set_identity_case_b3:
        status = _set_identity_b3 (session, identity); break;
    case _set_identity_case_b4:
        status = _set_identity_b4 (session, identity); break;

    default:
        fprintf (stderr, "invalid set_identity_case %i\n",
                 (int) set_identity_case);
        abort ();
    }

 end:
    if (status == PEP_STATUS_OK)
        {
        fprintf (stderr, "SUCCESS: %s on %s, case %s\n\n", __FUNCTION__, identity->address, set_identity_case_to_string (set_identity_case));
        sql_commit_transaction(session);
        }
    else
        {
            fprintf (stderr, "FAILURE: %s on %s, case %s: status %i (%s)\n\n", __FUNCTION__, identity->address, set_identity_case_to_string (set_identity_case), (int) status, pEp_status_to_string (status));
        sql_rollback_transaction(session);
        }
    return status;
}

// This will NOT call set_as_pEp_user, nor set_pEp_version; you have to do that separately.
DYNAMIC_API PEP_STATUS set_identity__ORIGINAL(
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
        reset_and_clear_bindings(session->set_pgp_keypair);
        sqlite3_bind_text(session->set_pgp_keypair, 1, identity->fpr, -1,
                SQLITE_STATIC);
        result = sqlite3_step(session->set_pgp_keypair);
        reset_and_clear_bindings(session->set_pgp_keypair);
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

PEP_STATUS update_pEp_user_trust_vals(PEP_SESSION session,
                                      pEp_identity* user) {
    
    if (!session || !user || EMPTYSTR(user->user_id))
        return PEP_ILLEGAL_VALUE;
    
    reset_and_clear_bindings(session->update_trust_to_pEp);
    sqlite3_bind_text(session->update_trust_to_pEp, 1, user->user_id, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->update_trust_to_pEp);
    reset_and_clear_bindings(session->update_trust_to_pEp);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    PEP_STATUS status = upgrade_pEp_version_by_user_id(session, user, 2, 0);
    
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
    reset_and_clear_bindings(session->set_as_pEp_user);
    sqlite3_bind_text(session->set_as_pEp_user, 1, user->user_id, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->set_as_pEp_user);
    reset_and_clear_bindings(session->set_as_pEp_user);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    status = update_pEp_user_trust_vals(session, user);
        
    return status;
}

// This ONLY sets the version flag. Must be called outside of a transaction.
PEP_STATUS set_pEp_version(PEP_SESSION session, pEp_identity* ident, unsigned int new_ver_major, unsigned int new_ver_minor) {

    if (!session || !ident || EMPTYSTR(ident->user_id) || EMPTYSTR(ident->address))
        return PEP_ILLEGAL_VALUE;

    reset_and_clear_bindings(session->set_pEp_version);
    sqlite3_bind_double(session->set_pEp_version, 1, new_ver_major);
    sqlite3_bind_double(session->set_pEp_version, 2, new_ver_minor);    
    sqlite3_bind_text(session->set_pEp_version, 3, ident->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_pEp_version, 4, ident->user_id, -1,
            SQLITE_STATIC);
    
    int result = sqlite3_step(session->set_pEp_version);
    reset_and_clear_bindings(session->set_pEp_version);
        
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
    
    reset_and_clear_bindings(session->upgrade_pEp_version_by_user_id);
    sqlite3_bind_int(session->upgrade_pEp_version_by_user_id, 1, new_ver_major);
    sqlite3_bind_int(session->upgrade_pEp_version_by_user_id, 2, new_ver_minor);    
    sqlite3_bind_text(session->upgrade_pEp_version_by_user_id, 3, ident->user_id, -1,
            SQLITE_STATIC);
    
    int result = sqlite3_step(session->upgrade_pEp_version_by_user_id);
    reset_and_clear_bindings(session->upgrade_pEp_version_by_user_id);
        
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
        reset_and_clear_bindings(session->exists_person);
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
                reset_and_clear_bindings(session->exists_person);
                return PEP_UNKNOWN_DB_ERROR;
        }
        reset_and_clear_bindings(session->exists_person);
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

PEP_STATUS delete_person(PEP_SESSION session, const char* user_id) {

    if (!session || EMPTYSTR(user_id))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = PEP_STATUS_OK;
    
    reset_and_clear_bindings(session->delete_person);
    sqlite3_bind_text(session->delete_person, 1, user_id, -1,
                      SQLITE_STATIC);
                      
    int result = sqlite3_step(session->delete_person);
    
    if (result != SQLITE_DONE)
        status = PEP_UNKNOWN_ERROR;
        
    reset_and_clear_bindings(session->delete_person);
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
    
    reset_and_clear_bindings(session->is_pEp_user);
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
            reset_and_clear_bindings(session->is_pEp_user);
            free(alias_default);
            return PEP_CANNOT_FIND_PERSON;
    }

    reset_and_clear_bindings(session->is_pEp_user);
    
    free(alias_default);
    return PEP_STATUS_OK;
}

PEP_STATUS is_own_address(PEP_SESSION session, const char* address, bool* is_own_addr)
{

    if (!session || !is_own_addr || EMPTYSTR(address))
        return PEP_ILLEGAL_VALUE;
    
    *is_own_addr = false;

    reset_and_clear_bindings(session->is_own_address);
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
            reset_and_clear_bindings(session->is_own_address);
            return PEP_RECORD_NOT_FOUND;
    }

    reset_and_clear_bindings(session->is_own_address);
    
    return PEP_STATUS_OK;
}

PEP_STATUS bind_own_ident_with_contact_ident(PEP_SESSION session,
                                             pEp_identity* own_ident, 
                                             pEp_identity* contact_ident) {
    if (!own_ident || !contact_ident || 
        !own_ident->address || !own_ident->user_id || !contact_ident->user_id)
        return PEP_ILLEGAL_VALUE;
        
    reset_and_clear_bindings(session->add_into_social_graph);
    sqlite3_bind_text(session->add_into_social_graph, 1, own_ident->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_into_social_graph, 2, own_ident->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_into_social_graph, 3, contact_ident->user_id, -1,
            SQLITE_STATIC);
        
    int result = sqlite3_step(session->add_into_social_graph);
    reset_and_clear_bindings(session->add_into_social_graph);
    
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
    
    reset_and_clear_bindings(session->has_id_contacted_address);
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
    reset_and_clear_bindings(session->has_id_contacted_address);
            
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

    reset_and_clear_bindings(session->get_own_address_binding_from_contact);
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
            
    reset_and_clear_bindings(session->remove_fpr_as_identity_default);
    sqlite3_bind_text(session->remove_fpr_as_identity_default, 1, fpr, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->remove_fpr_as_identity_default);
    reset_and_clear_bindings(session->remove_fpr_as_identity_default);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY; 

    reset_and_clear_bindings(session->remove_fpr_as_user_default);
    sqlite3_bind_text(session->remove_fpr_as_user_default, 1, fpr, -1,
                      SQLITE_STATIC);

    result = sqlite3_step(session->remove_fpr_as_user_default);
    reset_and_clear_bindings(session->remove_fpr_as_user_default);
    
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
            
    reset_and_clear_bindings(session->replace_identities_fpr);
    sqlite3_bind_text(session->replace_identities_fpr, 1, new_fpr, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->replace_identities_fpr, 2, old_fpr, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->replace_identities_fpr);
    reset_and_clear_bindings(session->replace_identities_fpr);
    
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
        
    reset_and_clear_bindings(session->update_trust_for_fpr);
    sqlite3_bind_int(session->update_trust_for_fpr, 1, comm_type);
    sqlite3_bind_text(session->update_trust_for_fpr, 2, fpr, -1,
            SQLITE_STATIC);
    int result = sqlite3_step(session->update_trust_for_fpr);
    reset_and_clear_bindings(session->update_trust_for_fpr);
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

    reset_and_clear_bindings(session->set_identity_flags);
    sqlite3_bind_int(session->set_identity_flags, 1, flags);
    sqlite3_bind_text(session->set_identity_flags, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_identity_flags, 3, identity->user_id, -1,
        SQLITE_STATIC);
        
    result = sqlite3_step(session->set_identity_flags);

    reset_and_clear_bindings(session->set_identity_flags);
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

    reset_and_clear_bindings(session->unset_identity_flags);
    sqlite3_bind_int(session->unset_identity_flags, 1, flags);
    sqlite3_bind_text(session->unset_identity_flags, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->unset_identity_flags, 3, identity->user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->unset_identity_flags);
    reset_and_clear_bindings(session->unset_identity_flags);
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

    reset_and_clear_bindings(session->set_ident_enc_format);
    sqlite3_bind_int(session->set_ident_enc_format, 1, format);
    sqlite3_bind_text(session->set_ident_enc_format, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_ident_enc_format, 3, identity->user_id, -1,
        SQLITE_STATIC);
        
    result = sqlite3_step(session->set_ident_enc_format);

    reset_and_clear_bindings(session->set_ident_enc_format);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

PEP_STATUS get_trust_by_userid(PEP_SESSION session, const char* user_id,
                                           labeled_int_list_t** trust_list)
{
    int result;

    if (!(session && user_id && user_id[0]))
        return PEP_ILLEGAL_VALUE;

    *trust_list = NULL;
    labeled_int_list_t* t_list = NULL;

    reset_and_clear_bindings(session->get_trust_by_userid);
    sqlite3_bind_text(session->get_trust_by_userid, 1, user_id, -1, SQLITE_STATIC);

    while ((result = sqlite3_step(session->get_trust_by_userid)) == SQLITE_ROW) {
        if (!t_list)
            t_list = new_labeled_int_list(sqlite3_column_int(session->get_trust_by_userid, 1),
                                         (const char *) sqlite3_column_text(session->get_trust_by_userid, 0));
        else
            labeled_int_list_add(t_list, sqlite3_column_int(session->get_trust_by_userid, 1),
                                (const char *) sqlite3_column_text(session->get_trust_by_userid, 0));
    }

    reset_and_clear_bindings(session->get_trust_by_userid);

    *trust_list = t_list;
        
    return PEP_STATUS_OK;
}

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

    reset_and_clear_bindings(session->replace_userid);
    sqlite3_bind_text(session->replace_userid, 1, new_uid, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_userid, 2, old_uid, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->replace_userid);
#ifndef NDEBUG
    if (result) {
        const char *errmsg = sqlite3_errmsg(session->db);
        log_event(session, "SQLite3 error", "replace_userid", errmsg, NULL);
    }
#endif // !NDEBUG
    reset_and_clear_bindings(session->replace_userid);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON; // May need clearer retval

    return PEP_STATUS_OK;
}

PEP_STATUS remove_key(PEP_SESSION session, const char* fpr) {
    
    if (!session || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    int result;

    reset_and_clear_bindings(session->delete_key);
    sqlite3_bind_text(session->delete_key, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->delete_key);
    reset_and_clear_bindings(session->delete_key);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR;

    return PEP_STATUS_OK;
}


PEP_STATUS refresh_userid_default_key(PEP_SESSION session, const char* user_id) {
    
    if (!session || !user_id)
        return PEP_ILLEGAL_VALUE;

    int result;

    reset_and_clear_bindings(session->refresh_userid_default_key);
    sqlite3_bind_text(session->refresh_userid_default_key, 1, user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->refresh_userid_default_key);
    reset_and_clear_bindings(session->refresh_userid_default_key);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;    
}

PEP_STATUS replace_main_user_fpr(PEP_SESSION session, const char* user_id,
                                 const char* new_fpr) {
    
    if (!session || !user_id || !new_fpr)
        return PEP_ILLEGAL_VALUE;

    int result;

    reset_and_clear_bindings(session->replace_main_user_fpr);
    sqlite3_bind_text(session->replace_main_user_fpr, 1, new_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr, 2, user_id, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->replace_main_user_fpr);
    reset_and_clear_bindings(session->replace_main_user_fpr);
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

    reset_and_clear_bindings(session->replace_main_user_fpr_if_equal);
    sqlite3_bind_text(session->replace_main_user_fpr, 1, new_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr_if_equal, 2, user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr_if_equal, 3, compare_fpr, -1,
            SQLITE_STATIC);            
    result = sqlite3_step(session->replace_main_user_fpr_if_equal);
    reset_and_clear_bindings(session->replace_main_user_fpr_if_equal);
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
    
    reset_and_clear_bindings(session->get_main_user_fpr);
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

    reset_and_clear_bindings(session->get_main_user_fpr);
    return status;
}

PEP_STATUS set_default_identity_fpr(PEP_SESSION session,
                                    const char* user_id,
                                    const char* address,
                                    const char* fpr) {

    if (!session || EMPTYSTR(user_id) || EMPTYSTR(address))
        return PEP_ILLEGAL_VALUE;
    // we accept NULL for deleting the fpr, but we don't accept empty strings
    if (fpr && !(*fpr))
        return PEP_ILLEGAL_VALUE;

    if (fpr) {
        // Make sure fpr is in the management DB
        PEP_STATUS status = set_pgp_keypair(session, fpr);
        if (status != PEP_STATUS_OK)
            return status;
    }

    int result;

    reset_and_clear_bindings(session->set_default_identity_fpr);
    sqlite3_bind_text(session->set_default_identity_fpr, 1, user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_default_identity_fpr, 2, address, -1,
            SQLITE_STATIC);
    if (fpr) {
        sqlite3_bind_text(session->set_default_identity_fpr, 3, fpr, -1,
                SQLITE_STATIC);
    }
    result = sqlite3_step(session->set_default_identity_fpr);
    reset_and_clear_bindings(session->set_default_identity_fpr);
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
    
    reset_and_clear_bindings(session->get_default_identity_fpr);
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

    reset_and_clear_bindings(session->get_default_identity_fpr);
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

    reset_and_clear_bindings(session->mark_compromised);
    sqlite3_bind_text(session->mark_compromised, 1, fpr, -1,
            SQLITE_STATIC);
    result = sqlite3_step(session->mark_compromised);
    reset_and_clear_bindings(session->mark_compromised);

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
    reset_and_clear_bindings(session->get_trust);

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

    reset_and_clear_bindings(session->get_trust);
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

    reset_and_clear_bindings(session->least_trust);
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

    reset_and_clear_bindings(session->least_trust);
    return status;
}

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

    reset_and_clear_bindings(session->crashdump);
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

    reset_and_clear_bindings(session->crashdump);
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

    reset_and_clear_bindings(session->languagelist);

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

    reset_and_clear_bindings(session->languagelist);
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

    reset_and_clear_bindings(session->i18n_token);
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

    reset_and_clear_bindings(session->i18n_token);
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}

static PEP_STATUS _get_sequence_value(PEP_SESSION session, const char *name,
        int32_t *value)
{
    if (!(session && name && value))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    reset_and_clear_bindings(session->sequence_value2);
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
    reset_and_clear_bindings(session->sequence_value2);

    return status;
}

static PEP_STATUS _increment_sequence_value(PEP_SESSION session,
        const char *name)
{
    if (!(session && name))
        return PEP_ILLEGAL_VALUE;

    reset_and_clear_bindings(session->sequence_value1);
    sqlite3_bind_text(session->sequence_value1, 1, name, -1, SQLITE_STATIC);
    int result = sqlite3_step(session->sequence_value1);
    assert(result == SQLITE_DONE);
    reset_and_clear_bindings(session->sequence_value1);
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
    
    reset_and_clear_bindings(session->set_revoked);
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
    
    reset_and_clear_bindings(session->set_revoked);
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

    reset_and_clear_bindings(session->get_revoked);
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

    reset_and_clear_bindings(session->get_revoked);

    return status;
}

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

    reset_and_clear_bindings(session->get_replacement_fpr);
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

    reset_and_clear_bindings(session->get_replacement_fpr);

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

    reset_and_clear_bindings(session->get_last_contacted);
    int result;

    while ((result = sqlite3_step(session->get_last_contacted)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity(
                (const char *) sqlite3_column_text(session->get_last_contacted, 1),
                NULL,
                (const char *) sqlite3_column_text(session->get_last_contacted, 0),
                NULL);
                
        assert(ident);
        if (ident == NULL) {
            reset_and_clear_bindings(session->get_last_contacted);
            return PEP_OUT_OF_MEMORY;
        }
    
        if (ident_list)
            identity_list_add(ident_list, ident);
        else
            ident_list = new_identity_list(ident);
    }

    reset_and_clear_bindings(session->get_last_contacted);
    
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


PEP_STATUS set_default_key(
        PEP_SESSION session,
        const pEp_identity *identity
    )
{
    if (!(session && identity && !EMPTYSTR(identity->user_id) &&
                !EMPTYSTR(identity->address) && !EMPTYSTR(identity->fpr)
                && identity->comm_type))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    // if this is a usable key following the comm_type set it as default
    if (identity->comm_type >= PEP_ct_security_by_obscurity) {
        status = set_default_identity_fpr(session, identity->user_id,
                identity->address, identity->fpr);
    }
    else /* identity->comm_type < PEP_ct_security_by_obscurity */ {
        // clear the default key
        status = set_default_identity_fpr(session, identity->user_id,
                identity->address, NULL);
    }

    return status;
}

DYNAMIC_API PEP_STATUS set_trust(
        PEP_SESSION session,
        const pEp_identity *identity
    )
{
    if (!(session && identity && !EMPTYSTR(identity->user_id) &&
                !EMPTYSTR(identity->address) && !EMPTYSTR(identity->fpr) &&
                identity->comm_type))
        return PEP_ILLEGAL_VALUE;

    sqlite3_exec(session->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    PEP_STATUS status = set_default_key(session, identity);
    if (status)
        goto rollback;

    status = update_trust_for_fpr(session, identity->fpr, identity->comm_type);
    if (status)
        goto rollback;

    sqlite3_exec(session->db, "COMMIT;", NULL, NULL, NULL);

    return PEP_STATUS_OK;

rollback:
    sqlite3_exec(session->db, "ROLLBACK;", NULL, NULL, NULL);
    return status;
}

