#define PEP_ENGINE_VERSION "0.6.0"

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

#include "sqlite3.h"

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

typedef struct _pEpSession {
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
    sqlite3_stmt *set_person;
    sqlite3_stmt *set_pgp_keypair;
    sqlite3_stmt *set_identity;
    sqlite3_stmt *set_trust;
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
    sqlite3_stmt *own_key_add;
    sqlite3_stmt *own_key_is_listed;
    sqlite3_stmt *own_key_retrieve;

    // sequence value
    sqlite3_stmt *sequence_value;

    // callbacks   
    examine_identity_t examine_identity;
    void *examine_management;
    void *sync_obj;
    messageToSend_t messageToSend;
    showHandshake_t showHandshake;

    // runtime config

    bool passive_mode;
    bool unencrypted_subject;
} pEpSession;

PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first);
void release_transport_system(PEP_SESSION session, bool out_last);

#ifdef NDEBUG
#define DEBUG_LOG(TITLE, ENTITY, DESC)
#else
#define DEBUG_LOG(TITLE, ENTITY, DESC) \
    log_event(session, (TITLE), (ENTITY), (DESC), "debug");
#endif

