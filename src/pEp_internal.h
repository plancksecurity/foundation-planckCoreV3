// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define PEP_ENGINE_VERSION "0.9.0"

// maximum attachment size to import as key 1MB, maximum of 20 attachments

#define MAX_KEY_SIZE (1024 * 1024)
#define MAX_KEYS_TO_IMPORT  20

// this is 20 trustwords with 79 chars max
#define MAX_TRUSTWORDS_SPACE (20 * 80)

// XML parameters string
#define PARMS_MAX 32768

// maximum busy wait time in ms
#define BUSY_WAIT_TIME 5000

// maximum line length for reading gpg.conf
#define MAX_LINELENGTH 1024

// default keyserver
#ifndef DEFAULT_KEYSERVER
#define DEFAULT_KEYSERVER "hkp://keys.gnupg.net"
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


#include "platform.h"

#ifdef WIN32
#define LOCAL_DB windoze_local_db()
#define SYSTEM_DB windoze_system_db()
#define LIBGPGME "libgpgme-11.dll"
#else // UNIX
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
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
#include <ctype.h>
#include <math.h>

#ifdef SQLITE3_FROM_OS
#include <sqlite3.h>
#else
#include "sqlite3.h"
#endif

#include "pEpEngine.h"

// If not specified, build for GPG
#ifndef USE_NETPGP
#ifndef USE_GPG
#define USE_GPG
#endif
#endif

#ifdef USE_GPG
#include "pgp_gpg_internal.h"
#elif defined(USE_NETPGP)
#include "pgp_netpgp_internal.h"
#endif

#include "keymanagement.h"
#include "cryptotech.h"
#include "transport.h"
#include "sync.h"

#define NOT_IMPLEMENTED assert(0); return PEP_UNKNOWN_ERROR;

struct _pEpSession;
typedef struct _pEpSession pEpSession;
struct _pEpSession {
    const char *version;
#ifdef USE_GPG
    gpgme_ctx_t ctx;
#elif defined(USE_NETPGP)
    pEpNetPGPSession ctx;
#endif

    PEP_cryptotech_t *cryptotech;
    PEP_transport_t *transports;

    sqlite3 *db;
    sqlite3 *system_db;

    sqlite3_stmt *log;
    sqlite3_stmt *trustword;
    sqlite3_stmt *get_identity;
    sqlite3_stmt *get_identity_without_trust_check;
    sqlite3_stmt *get_identities_by_address;
    sqlite3_stmt *replace_identities_fpr;
    sqlite3_stmt *replace_main_user_fpr;
    sqlite3_stmt *get_main_user_fpr;
    sqlite3_stmt *refresh_userid_default_key;
    sqlite3_stmt *remove_fpr_as_default;
    sqlite3_stmt *set_person;
    sqlite3_stmt *update_person;
    sqlite3_stmt *exists_person;    
    sqlite3_stmt *set_as_pep_user;
    sqlite3_stmt *is_pep_user;
    sqlite3_stmt *set_device_group;
    sqlite3_stmt *get_device_group;
    sqlite3_stmt *set_pgp_keypair;
    sqlite3_stmt *set_identity_entry;
    sqlite3_stmt *update_identity_entry;
    sqlite3_stmt *exists_identity_entry;        
    sqlite3_stmt *set_identity_flags;
    sqlite3_stmt *unset_identity_flags;
    sqlite3_stmt *set_trust;
    sqlite3_stmt *update_trust;
    sqlite3_stmt *update_trust_to_pep;    
    sqlite3_stmt *exists_trust_entry;
    sqlite3_stmt *update_trust_for_fpr;
    sqlite3_stmt *get_trust;
    sqlite3_stmt *least_trust;
    sqlite3_stmt *mark_compromized;
    sqlite3_stmt *reset_trust;
    sqlite3_stmt *crashdump;
    sqlite3_stmt *languagelist;
    sqlite3_stmt *i18n_token;
    sqlite3_stmt *replace_userid;

    // blacklist
    sqlite3_stmt *blacklist_add;
    sqlite3_stmt *blacklist_delete;
    sqlite3_stmt *blacklist_is_listed;
    sqlite3_stmt *blacklist_retrieve;
    
    // Own keys
    sqlite3_stmt *own_key_is_listed;
    sqlite3_stmt *own_identities_retrieve;
    sqlite3_stmt *own_keys_retrieve;
    sqlite3_stmt *get_user_default_key;
        
    sqlite3_stmt *get_default_own_userid;

//    sqlite3_stmt *set_own_key;

    // sequence value
    sqlite3_stmt *sequence_value1;
    sqlite3_stmt *sequence_value2;
    sqlite3_stmt *sequence_value3;

    // revoked keys
    sqlite3_stmt *set_revoked;
    sqlite3_stmt *get_revoked;

    // mistrusted
    sqlite3_stmt* add_mistrusted_key;
    sqlite3_stmt* is_mistrusted_key;    
    sqlite3_stmt* delete_mistrusted_key;
    
    // aliases
    sqlite3_stmt *get_userid_alias_default;
    sqlite3_stmt *add_userid_alias;

    // callbacks
    examine_identity_t examine_identity;
    void *examine_management;
    void *sync_management;
    void *sync_obj;
    messageToSend_t messageToSend;
    notifyHandshake_t notifyHandshake;
    inject_sync_msg_t inject_sync_msg;
    retrieve_next_sync_msg_t retrieve_next_sync_msg;

    // key sync
    pEpSession* sync_session;
    DeviceState_state sync_state;
    void* sync_state_payload;
    char sync_uuid[37];
    time_t LastCannotDecrypt;
    time_t LastUpdateRequest;

    // runtime config

    bool passive_mode;
    bool unencrypted_subject;
    bool keep_sync_msg;
    bool service_log;

    // mistrust undo cache
    pEp_identity* cached_mistrusted;
    
#ifdef DEBUG_ERRORSTACK
    stringlist_t* errorstack;
#endif
};


PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first);
void release_transport_system(PEP_SESSION session, bool out_last);

/* NOT to be exposed to the outside!!! */
PEP_STATUS encrypt_only(
        PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
        size_t psize, char **ctext, size_t *csize
);

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

typedef enum _normalize_hex_rest_t {
    accept_hex,
    ignore_hex,
    reject_hex
} normalize_hex_res_t;

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
static inline int _unsigned_signed_strcmp(const unsigned char* bytestr, const char* charstr, int bytestr_size) {
    int charstr_len = strlen(charstr);
    if (charstr_len != bytestr_size)
        return -1; // we don't actually care except that it's non-zero
    return memcmp(bytestr, charstr, bytestr_size);
}

// This is just a horrible example of C type madness. UTF-8 made me do it.
static inline char* _pep_subj_copy() {
#ifndef WIN32
    unsigned char pepstr[] = PEP_SUBJ_STRING;
    void* retval = calloc(1, sizeof(unsigned char)*PEP_SUBJ_BYTELEN + 1);
    memcpy(retval, pepstr, PEP_SUBJ_BYTELEN);
    return (char*)retval;
#else
    return strdup("pEp");
#endif
}

static inline bool is_me(PEP_SESSION session, pEp_identity* test_ident) {
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

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
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

static inline void _init_globals() {
    _pEp_rand_max_bits = ceil(log2(RAND_MAX));
    _pEp_log2_36 = log2(36);
}
