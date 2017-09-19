// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define PEP_ENGINE_VERSION "0.8.0"

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

#ifndef PEP_MSG_VERSION_KEY
#define PEP_MSG_VERSION_KEY "pEp-Message-Version: "
#define PEP_MSG_VERSION_KEY_LC "pep-message-version: "
#define PEP_MSG_VERSION_KEY_LEN 21
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

#ifdef SQLITE3_FROM_OS
#include <sqlite3.h>
#else
#include "sqlite3.h"
#endif

#define _EXPORT_PEP_ENGINE_DLL
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
    sqlite3_stmt *replace_identities_fpr;
    sqlite3_stmt *set_person;
    sqlite3_stmt *set_device_group;
    sqlite3_stmt *get_device_group;
    sqlite3_stmt *set_pgp_keypair;
    sqlite3_stmt *set_identity;
    sqlite3_stmt *set_identity_flags;
    sqlite3_stmt *unset_identity_flags;
    sqlite3_stmt *set_trust;
    sqlite3_stmt *update_trust_for_fpr;
    sqlite3_stmt *get_trust;
    sqlite3_stmt *least_trust;
    sqlite3_stmt *mark_compromized;
    sqlite3_stmt *reset_trust;
    sqlite3_stmt *crashdump;
    sqlite3_stmt *languagelist;
    sqlite3_stmt *i18n_token;

    // blacklist
    sqlite3_stmt *blacklist_add;
    sqlite3_stmt *blacklist_delete;
    sqlite3_stmt *blacklist_is_listed;
    sqlite3_stmt *blacklist_retrieve;
    
    // Own keys
    sqlite3_stmt *own_key_is_listed;
    sqlite3_stmt *own_identities_retrieve;
    sqlite3_stmt *own_keys_retrieve;
    sqlite3_stmt *set_own_key;

    // sequence value
    sqlite3_stmt *sequence_value1;
    sqlite3_stmt *sequence_value2;
    sqlite3_stmt *sequence_value3;

    // revoked keys
    sqlite3_stmt *set_revoked;
    sqlite3_stmt *get_revoked;

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

static inline bool _identity_me(
        pEp_identity * identity
    )
{
    return identity->user_id && strcmp(identity->user_id, PEP_OWN_USERID) == 0;
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
    unsigned char pepstr[] = PEP_SUBJ_STRING;
    void* retval = calloc(1, sizeof(unsigned char)*PEP_SUBJ_BYTELEN + 1);
    memcpy(retval, pepstr, PEP_SUBJ_BYTELEN);
    return (char*)retval;
}

#ifdef DEBUG_ERRORSTACK
    PEP_STATUS session_add_error(PEP_SESSION session, const char* file, unsigned line, PEP_STATUS status);
    #define ADD_TO_LOG(status)   session_add_error(session, __FILE__, __LINE__, (status))
    #define GOTO(label)          do{ (void)session_add_error(session, __FILE__, __LINE__, status); goto label; }while(0)
#else
    #define ADD_TO_LOG(status)   (status)
    #define GOTO(label)          goto label
#endif
