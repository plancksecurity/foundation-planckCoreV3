/**
 * @file    pEp_internal.h
 * @brief   pEp internal structs, functions, defines, and values
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_INTERNAL_H
#define PEP_INTERNAL_H

// maximum attachment size to import as key 25MB, maximum of 20 attachments
#define MAX_KEY_SIZE (25 * 1024 * 1024)
#define MAX_KEYS_TO_IMPORT  20

#define KEY_EXPIRE_DELTA (60 * 60 * 24 * 365)

// this is 20 trustwords with 79 chars max
#define MAX_TRUSTWORDS_SPACE (20 * 80)

// XML parameters string
#define PARMS_MAX 32768

// maximum busy wait time in ms
#define BUSY_WAIT_TIME 5000

// default keyserver
#ifndef DEFAULT_KEYSERVER
#define DEFAULT_KEYSERVER "hkps://keys.openpgp.org"
#endif

// crashdump constants
#ifndef CRASHDUMP_DEFAULT_LINES
#define CRASHDUMP_DEFAULT_LINES 100
#endif
#define CRASHDUMP_MAX_LINES 32767

// p≡p full string, NUL-terminated
#ifndef PEP_SUBJ_STRING
#define PEP_SUBJ_STRING {0x70,0xE2,0x89,0xA1,0x70,0x00}
#define PEP_SUBJ_BYTELEN 5
#endif

#ifndef PEP_SUBJ_KEY
#define PEP_SUBJ_KEY "Subject: "
#define PEP_SUBJ_KEY_LC "subject: "
#define PEP_SUBJ_KEY_LEN 9
#endif

#ifndef PEP_MSG_WRAP_KEY
#define PEP_MSG_WRAP_KEY "pEp-Wrapped-Message-Info: "
#define PEP_MSG_WRAP_KEY_LC "pep-wrapped-message-info: "
#define PEP_MSG_WRAP_KEY_LEN 26
#endif

#ifndef X_PEP_MSG_WRAP_KEY
#define X_PEP_MSG_WRAP_KEY "X-pEp-Wrapped-Message-Info"
#endif

#ifndef X_PEP_SNDR_FPR_KEY
#define X_PEP_SNDR_FPR_KEY "X-pEp-Sender-FPR"
#endif
 
#ifndef X_PEP_MSG_VER_KEY
#define X_PEP_MSG_VER_KEY "X-pEp-Message-Version"
#endif

#define VER_1_0 "1.0"
#define VER_2_0 "2.0"
#define VER_2_1 "2.1"
#define VER_2_2 "2.2"

#include "platform.h"

#ifdef WIN32
#define KEYS_DB windoze_keys_db()
#define LOCAL_DB windoze_local_db()
#define SYSTEM_DB windoze_system_db()
#else // UNIX
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#ifdef NDEBUG
#define LOCAL_DB unix_local_db()
#else
#define LOCAL_DB unix_local_db(false)
#define LOCAL_DB_RESET unix_local_db(true)
#endif
#ifdef ANDROID
#define SYSTEM_DB android_system_db()
#else
#define SYSTEM_DB unix_system_db()
#endif
#endif

#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#ifdef SQLITE3_FROM_OS
#include <sqlite3.h>
#else
#include "sqlite3.h"
#endif

#include "pEpEngine.h"
#include "key_reset.h"

#include "pEpEngine_internal.h"
#include "key_reset_internal.h"
#include "group_internal.h"
#include "keymanagement_internal.h"
#include "message_api_internal.h"

// If not specified, build for Sequoia
#ifndef USE_SEQUOIA
#define USE_SEQUOIA
#endif

#if defined(USE_SEQUOIA)
#include "pgp_sequoia_internal.h"
#endif

#include "../asn.1/Distribution.h"
#include "../asn.1/Sync.h"

#include "keymanagement.h"
#include "cryptotech.h"
#include "transport.h"
#include "sync_api.h"
#include "Sync_func.h"


#define NOT_IMPLEMENTED assert(0); return PEP_UNKNOWN_ERROR;

struct _pEpSession;
typedef struct _pEpSession pEpSession;
/**
 *  @struct    _pEpSession
 *  
 *  @brief    TODO
 *  
 */
struct _pEpSession {
    const char *version;
    messageToSend_t messageToSend;

#if defined(USE_SEQUOIA)
    sqlite3 *key_db;
    struct {
        sqlite3_stmt *begin_transaction;
        sqlite3_stmt *commit_transaction;
        sqlite3_stmt *rollback_transaction;
        sqlite3_stmt *cert_find;
        sqlite3_stmt *tsk_find;
        sqlite3_stmt *cert_find_by_keyid;
        sqlite3_stmt *tsk_find_by_keyid;
        sqlite3_stmt *cert_find_by_email;
        sqlite3_stmt *tsk_find_by_email;
        sqlite3_stmt *cert_all;
        sqlite3_stmt *tsk_all;
        sqlite3_stmt *cert_save_insert_primary;
        sqlite3_stmt *cert_save_insert_subkeys;
        sqlite3_stmt *cert_save_insert_userids;
        sqlite3_stmt *delete_keypair;
    } sq_sql;

    pgp_policy_t policy;
#endif

    PEP_cryptotech_t *cryptotech;
    PEP_CIPHER_SUITE cipher_suite;
    
    char* curr_passphrase;
    bool new_key_pass_enable;
    char* generation_passphrase;
    
    PEP_transport_t *transports;

    sqlite3 *db;
    sqlite3 *system_db;

    sqlite3_stmt *log;
    sqlite3_stmt *trustword;
    sqlite3_stmt *get_identity;
    sqlite3_stmt *get_identity_without_trust_check;
    sqlite3_stmt *get_identities_by_address;
    sqlite3_stmt *get_identities_by_userid;
    sqlite3_stmt *get_identities_by_main_key_id;
    sqlite3_stmt *replace_identities_fpr;
    sqlite3_stmt *replace_main_user_fpr;
    sqlite3_stmt *replace_main_user_fpr_if_equal;
    sqlite3_stmt *get_main_user_fpr;
    sqlite3_stmt *set_default_identity_fpr;
    sqlite3_stmt *get_default_identity_fpr;
    sqlite3_stmt *refresh_userid_default_key;
    sqlite3_stmt *delete_key;
    sqlite3_stmt *remove_fpr_as_identity_default;
    sqlite3_stmt *remove_fpr_as_user_default;
    sqlite3_stmt *set_person;
    sqlite3_stmt *update_person;
    sqlite3_stmt *delete_person;
    sqlite3_stmt *exists_person;    
    sqlite3_stmt *set_as_pEp_user;
    sqlite3_stmt *is_pEp_user;
    sqlite3_stmt *upgrade_pEp_version_by_user_id;
    sqlite3_stmt *add_into_social_graph;
    sqlite3_stmt *get_own_address_binding_from_contact;
    sqlite3_stmt *set_revoke_contact_as_notified;
    sqlite3_stmt *get_contacted_ids_from_revoke_fpr;
    sqlite3_stmt *was_id_for_revoke_contacted;
    sqlite3_stmt *has_id_contacted_address;
    sqlite3_stmt *get_last_contacted;
    // sqlite3_stmt *set_device_group;
    // sqlite3_stmt *get_device_group;
    sqlite3_stmt *set_pgp_keypair;
    sqlite3_stmt *set_pgp_keypair_flags;
    sqlite3_stmt *unset_pgp_keypair_flags;
    sqlite3_stmt *set_identity_entry;
    sqlite3_stmt *update_identity_entry;
    sqlite3_stmt *exists_identity_entry;
    sqlite3_stmt *force_set_identity_username;
    sqlite3_stmt *set_identity_flags;
    sqlite3_stmt *unset_identity_flags;
    sqlite3_stmt *set_ident_enc_format;
    sqlite3_stmt *set_pEp_version; 
    sqlite3_stmt *clear_trust_info;   
    sqlite3_stmt *set_trust;
    sqlite3_stmt *update_trust;
    sqlite3_stmt *exists_trust_entry;
    sqlite3_stmt *update_trust_to_pEp;
    sqlite3_stmt *update_trust_for_fpr;
    sqlite3_stmt *get_trust;
    sqlite3_stmt *get_trust_by_userid;
    sqlite3_stmt *least_trust;
    sqlite3_stmt *update_key_sticky_bit_for_user;
    sqlite3_stmt *is_key_sticky_for_user;
    sqlite3_stmt *mark_compromised;
    sqlite3_stmt *reset_trust;
    sqlite3_stmt *crashdump;
    sqlite3_stmt *languagelist;
    sqlite3_stmt *i18n_token;
    sqlite3_stmt *replace_userid;

    // Keys
    sqlite3_stmt *own_key_is_listed;
    sqlite3_stmt *is_own_address;
    sqlite3_stmt *own_identities_retrieve;
    sqlite3_stmt *own_keys_retrieve;
    sqlite3_stmt *key_identities_retrieve;
    sqlite3_stmt *get_user_default_key;
    sqlite3_stmt *get_all_keys_for_user;
        
    sqlite3_stmt *get_default_own_userid;

    // groups
    sqlite3_stmt *create_group;
    sqlite3_stmt *enable_group;
    sqlite3_stmt *disable_group;
    sqlite3_stmt *exists_group_entry;
    sqlite3_stmt *group_add_member;
    sqlite3_stmt *group_delete_member;
    sqlite3_stmt *group_join;
    sqlite3_stmt *leave_group;
    sqlite3_stmt *set_group_member_status;
    sqlite3_stmt *get_all_members;
    sqlite3_stmt *get_active_members;
    sqlite3_stmt *get_active_groups;
    sqlite3_stmt *get_all_groups;
    sqlite3_stmt *add_own_membership_entry;
    sqlite3_stmt *get_own_membership_status;
    sqlite3_stmt *retrieve_own_membership_info_for_group_and_ident;
    sqlite3_stmt *retrieve_own_membership_info_for_group;
    sqlite3_stmt *get_group_manager;
    sqlite3_stmt *is_invited_group_member;
    sqlite3_stmt *is_active_group_member;
    sqlite3_stmt *is_group_active;

//    sqlite3_stmt *set_own_key;

    // sequence value
    sqlite3_stmt *sequence_value1;
    sqlite3_stmt *sequence_value2;

    // revoked keys
    sqlite3_stmt *set_revoked;
    sqlite3_stmt *get_revoked;
    sqlite3_stmt *get_replacement_fpr;

    // mistrusted
    sqlite3_stmt* add_mistrusted_key;
    sqlite3_stmt* is_mistrusted_key;    
    sqlite3_stmt* delete_mistrusted_key;
    
    // aliases
    sqlite3_stmt *get_userid_alias_default;
    sqlite3_stmt *add_userid_alias;

    // callbacks
    notifyHandshake_t notifyHandshake;
    inject_sync_event_t inject_sync_event;
    retrieve_next_sync_event_t retrieve_next_sync_event;
    ensure_passphrase_t ensure_passphrase;

    // pEp Sync
    void *sync_management;
    void *sync_obj;
    struct Sync_state_s sync_state;

//     void* sync_state_payload;
//     char sync_uuid[37];
//     time_t LastCannotDecrypt;
//     time_t LastUpdateRequest;

    // runtime config

    bool passive_mode;
    bool unencrypted_subject;
    bool service_log;
    
#ifndef NDEBUG
    int debug_color;
#endif
};


/**
 *  <!--       init_transport_system()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  in_first       bool
 *  
 *  @retval     PEP_STATUS_OK
 */
PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first);

/**
 *  <!--       release_transport_system()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle
 *  @param[in]  out_last       bool
 *  
 */
void release_transport_system(PEP_SESSION session, bool out_last);

/**
 *  @internal
 * 
 *  <!--       encrypt_only()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session     session handle 
 *  @param[in]  keylist     const stringlist_t*
 *  @param[in]  ptext       const char*
 *  @param[in]  psize       size_t
 *  @param[in]  ctext       char**
 *  @param[in]  csize       size_t*
 *  
 *  @warning    NOT to be exposed to the outside!!!!!
 */
PEP_STATUS encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
);

/**
 *  <!--       decorate_message()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  msg          message*
 *  @param[in]  rating       PEP_rating
 *  @param[in]  keylist      stringlist_t*
 *  @param[in]  add_version  bool
 *  @param[in]  clobber      bool
 *  
 */
void decorate_message(
    PEP_SESSION session,
    message *msg,
    PEP_rating rating,
    stringlist_t *keylist,
    bool add_version,
    bool clobber);

#if defined(NDEBUG) || defined(NOLOG)
#define DEBUG_LOG(TITLE, ENTITY, DESC)
#else
#ifdef ANDROID
#include <android/log.h>
#define  LOG_MORE(...)  __android_log_print(ANDROID_LOG_DEBUG, "pEpEngine", " %s :: %s :: %s :: %s ", __VA_ARGS__);
#else
#include <stdio.h>
#define  LOG_MORE(...)  fprintf(stderr, "pEpEngine DEBUG_LOG('%s','%s','%s','%s')\n", __VA_ARGS__);
#endif
#define DEBUG_LOG(TITLE, ENTITY, DESC) {\
    log_event(session, (TITLE), (ENTITY), (DESC), "debug " __FILE__ ":" S_LINE);\
    LOG_MORE((TITLE), (ENTITY), (DESC), __FILE__ ":" S_LINE)\
}
#endif

/**
 *  @enum    normalize_hex_res_t
 *  
 *  @brief    TODO
 *  
 */
typedef enum _normalize_hex_rest_t {
    accept_hex,
    ignore_hex,
    reject_hex
} normalize_hex_res_t;

/**
 *  <!--       _normalize_hex()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  hex         char*
 *  
 *  @retval     accept_hex
 *  @retval     irgnore_hex
 *  @retval     reject_hex
 */
static inline normalize_hex_res_t _normalize_hex(char *hex) 
{
    if (*hex >= '0' && *hex <= '9')
        return accept_hex;

    if (*hex >= 'A' && *hex <= 'F') {
        *hex += 'a' - 'A';
        return accept_hex;
    }

    if (*hex >= 'a' && *hex <= 'f') 
        return accept_hex;

    if (*hex == ' ') 
        return ignore_hex;

    return reject_hex;
}

// Space tolerant and case insensitive fingerprint string compare
/**
 *  <!--       _compare_fprs()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  fpra         const char*
 *  @param[in]  fpras        size_t
 *  @param[in]  fprb         const char*
 *  @param[in]  fprbs        size_t
 *  @param[in]  comparison   int*
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_TRUSTWORDS_FPR_WRONG_LENGTH
 */
static inline PEP_STATUS _compare_fprs(
        const char* fpra,
        size_t fpras,
        const char* fprb,
        size_t fprbs,
        int* comparison)
{

    size_t ai = 0;
    size_t bi = 0;
    size_t significant = 0;
    int _comparison = 0;
    const int _FULL_FINGERPRINT_LENGTH = 40;
   
    // First compare every non-ignored chars until an end is reached
    while(ai < fpras && bi < fprbs)
    {
        char fprac = fpra[ai];
        char fprbc = fprb[bi];
        normalize_hex_res_t fprah = _normalize_hex(&fprac);
        normalize_hex_res_t fprbh = _normalize_hex(&fprbc);

        if(fprah == reject_hex || fprbh == reject_hex)
            return PEP_ILLEGAL_VALUE;

        if ( fprah == ignore_hex )
        {
            ai++;
        }
        else if ( fprbh == ignore_hex )
        {
            bi++;
        }
        else
        {
            if(fprac != fprbc && _comparison == 0 )
            {
                _comparison = fprac > fprbc ? 1 : -1;
            }

            significant++;
            ai++;
            bi++;

        } 
    }

    // Bail out if we didn't got enough significnt chars
    if (significant != _FULL_FINGERPRINT_LENGTH )
        return PEP_TRUSTWORDS_FPR_WRONG_LENGTH;

    // Then purge remaining chars, all must be ignored chars
    while ( ai < fpras )
    {
        char fprac = fpra[ai];
        normalize_hex_res_t fprah = _normalize_hex(&fprac);
        if( fprah == reject_hex )
            return PEP_ILLEGAL_VALUE;
        if ( fprah != ignore_hex )
            return PEP_TRUSTWORDS_FPR_WRONG_LENGTH;
        ai++;
    }
    while ( bi < fprbs )
    {
        char fprbc = fprb[bi];
        normalize_hex_res_t fprbh = _normalize_hex(&fprbc);
        if( fprbh == reject_hex )
            return PEP_ILLEGAL_VALUE;
        if ( fprbh != ignore_hex )
            return PEP_TRUSTWORDS_FPR_WRONG_LENGTH;
        bi++;
    }

    *comparison = _comparison;
    return PEP_STATUS_OK;
}

/**
 *  <!--       _same_fpr()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  fpra         const char*
 *  @param[in]  fpras        size_t
 *  @param[in]  fprb         const char*
 *  @param[in]  fprbs        size_t
 *  
 *  @retval     0 on equal fingerprints
 *  @retval     non-zero if not equal 
 */
static inline int _same_fpr(
        const char* fpra,
        size_t fpras,
        const char* fprb,
        size_t fprbs
    )
{
    // illegal values are ignored, and considered not same.
    int comparison = 1;

    _compare_fprs(fpra, fpras, fprb, fprbs, &comparison);

    return comparison == 0;
}

// size is the length of the bytestr that's coming in. This is really only intended
// for comparing two full strings. If charstr's length is different from bytestr_size,
// we'll return a non-zero value.
/**
 *  @internal
 * 
 *  <!--       _unsigned_signed_strcmp()       -->
 *  
 *  @brief      Compare an unsigned sequence of bytes with the input string.
 *              This is really only intended for comparing two full strings. 
 *              If charstr's length is different from bytestr_size,
 *              we'll return a non-zero value.
 * 
 *  @param[in]  bytestr         byte string (unsigned char data)
 *  @param[in]  charstr         character string (NUL-terminated)
 *  @param[in]  bytestr_size    length of byte string passed in
 * 
 *  @retval     0           if equal
 *  @retval     non-zero    if not equal
 *  
 */
static inline int _unsigned_signed_strcmp(const unsigned char* bytestr, const char* charstr, int bytestr_size) {
    int charstr_len = strlen(charstr);
    if (charstr_len != bytestr_size)
        return -1; // we don't actually care except that it's non-zero
    return memcmp(bytestr, charstr, bytestr_size);
}

// This is just a horrible example of C type madness. UTF-8 made me do it.
/**
 *  <!--       _pEp_subj_copy()       -->
 *  
 *  @brief            TODO
 *  
 *  
 */
static inline char* _pEp_subj_copy() {
#ifndef WIN32
    unsigned char pEpstr[] = PEP_SUBJ_STRING;
    void* retval = calloc(1, sizeof(unsigned char)*PEP_SUBJ_BYTELEN + 1);
    memcpy(retval, pEpstr, PEP_SUBJ_BYTELEN);
    return (char*)retval;
#else
    return strdup("pEp");
#endif
}

/**
 *  <!--       is_me()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  session        session handle 
 *  @param[in]  test_ident     const pEp_identity*
 *  
 *  @retval     true
 *  @retval     false
 */
static inline bool is_me(PEP_SESSION session, const pEp_identity* test_ident) {
    bool retval = false;
    if (test_ident && test_ident->user_id) {
        char* def_id = NULL;
        get_default_own_userid(session, &def_id);
        if (test_ident->me || 
            (def_id && strcmp(def_id, test_ident->user_id) == 0)) {
            retval = true;
        }
        free(def_id);
    }
    return retval;
}

/**
 *  <!--       pEp_version_numeric()       -->
 *  
 *  @brief
 *  
 *  @param[in]  version_str         const char*
 *  
 *  @retval     float   version number
 *  @retval     0 on failure
 */
static inline float pEp_version_numeric(const char* version_str) {
    float retval = 0;    
        
    if (!version_str || sscanf(version_str, "%f", &retval) != 1)
        return 0;
        
    return retval;    
}

/**
 *  <!--       pEp_version_major_minor()       -->
 *  
 *  @brief get major and minor numbers as integers from version string 
 *  
 *  @param[in]   version_str   const char*
 *  @param[out]  major         unsigned int*
 *  @param[out]  minor         unsigned int*
 *  
 */
static inline void pEp_version_major_minor(const char* version_str, unsigned int* major, unsigned int* minor) {
    if (!major || !minor)
        return;
                
    if (!version_str || sscanf(version_str, "%u.%u", major, minor) != 2) {
        *major = 0;
        *minor = 0;
    }
        
    return;    
}

/**
 *  <!--       compare_versions()       -->
 *  
 *  @brief compares two versions by major and minor version numbers 
 *  
 *  @param[in]  first_maj       unsigned int
 *  @param[in]  first_min       unsigned int
 *  @param[in]  second_maj      unsigned int
 *  @param[in]  second_min      unsigned int
 *  
 *  @retval     1 when first is higher version
 *  @retval     -1 when first is lower version
 *  @retval     0 when versions are equal 
 */
static inline int compare_versions(unsigned int first_maj, unsigned int first_min,
                                   unsigned int second_maj, unsigned int second_min) {
    if (first_maj > second_maj)
        return 1;
    if (first_maj < second_maj)
        return -1;
    if (first_min > second_min)
        return 1;
    if (first_min < second_min)
        return -1;
    return 0;    
}

/**
 *  <!--       set_min_version()       -->
 *  
 *  @brief determine the smaler version from two versions 
 *  
 *  @param[in]  first_maj        unsigned int
 *  @param[in]  first_minor      unsigned int
 *  @param[in]  second_maj       unsigned int
 *  @param[in]  second_minor     unsigned int
 *  @param[out]  result_maj       unsigned int*
 *  @param[out]  result_minor     unsigned int*
 *  
 */
static inline void set_min_version(unsigned int first_maj, unsigned int first_minor,
                                   unsigned int second_maj, unsigned int second_minor,
                                   unsigned int* result_maj, unsigned int* result_minor) {
    int result = compare_versions(first_maj, first_minor, second_maj, second_minor);
    if (result < 0) {
        *result_maj = first_maj;
        *result_minor = first_minor;
    }
    else {
        *result_maj = second_maj;
        *result_minor = second_minor;
    }    
}

/**
 *  <!--       set_max_version()       -->
 *  
 *  @brief determine the greater version out of two versions 
 *  
 *  @param[in]   first_maj        unsigned int
 *  @param[in]   first_minor      unsigned int
 *  @param[in]   second_maj       unsigned int
 *  @param[in]   second_minor     unsigned int
 *  @param[out]  result_maj       unsigned int*
 *  @param[out]  result_minor     unsigned int*
 *  
 */
static inline void set_max_version(unsigned int first_maj, unsigned int first_minor,
                                   unsigned int second_maj, unsigned int second_minor,
                                   unsigned int* result_maj, unsigned int* result_minor) {
    int result = compare_versions(first_maj, first_minor, second_maj, second_minor);
    if (result > 0) {
        *result_maj = first_maj;
        *result_minor = first_minor;
    }
    else {
        *result_maj = second_maj;
        *result_minor = second_minor;
    }    
}

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
#endif

#ifndef PASS_ERROR
#define PASS_ERROR(ST) (ST == PEP_PASSPHRASE_REQUIRED || ST == PEP_WRONG_PASSPHRASE || ST == PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED)
#endif

#ifndef IS_PGP_CT
#define IS_PGP_CT(CT) (((CT) | PEP_ct_confirmed) == PEP_ct_OpenPGP)
#endif

#ifndef _MIN
#define _MIN(A, B) ((B) > (A) ? (A) : (B))
#endif
#ifndef _MAX
#define _MAX(A, B) ((B) > (A) ? (B) : (A))
#endif

// These are globals used in generating message IDs and should only be
// computed once, as they're either really constants or OS-dependent

extern int _pEp_rand_max_bits;
extern double _pEp_log2_36;

/**
 *  <!--       _init_globals()       -->
 *
 *  @internal
 *
 *  @brief            TODO
 *  
 *  Please leave _patch_asn1_codec COMMENTED OUT unless you're working
 *  in a branch or patching the asn1 is a solution
 */
static inline void _init_globals() {
    _pEp_rand_max_bits = (int) ceil(log2((double) RAND_MAX));
    _pEp_log2_36 = log2(36);
}


// spinlock implementation

/**
 *  <!--       Sqlite3_step()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  stmt         sqlite3_stmt*
 *  
 */
static inline int Sqlite3_step(sqlite3_stmt* stmt)
{
    int rc;
    do {
        rc = sqlite3_step(stmt);
    } while (rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
    return rc;
}

/**
 *  @internal
 *
 *  <!--       _add_auto_consume()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *msg        message
 *
 */
static inline void _add_auto_consume(message* msg) {
    add_opt_field(msg, "pEp-auto-consume", "yes");
    msg->in_reply_to = stringlist_add(msg->in_reply_to, "pEp-auto-consume@pEp.foundation");
}


#endif
