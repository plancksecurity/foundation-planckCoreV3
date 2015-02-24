#define PEP_ENGINE_VERSION "0.5.0"

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

#ifndef NO_GPG
#include <gpgme.h>
#endif

#include "sqlite3.h"

#define _EXPORT_PEP_ENGINE_DLL
#include "pEpEngine.h"
#ifndef NO_GPG
#include "pgp_gpg_internal.h"
#endif

#include "cryptotech.h"
#include "transport.h"

#define NOT_IMPLEMENTED assert(0)

typedef struct _pEpSession {
    const char *version;
#ifndef NO_GPG
    gpgme_ctx_t ctx;
#endif

    PEP_cryptotech_t *cryptotech;
    PEP_transport_t *transports;

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
} pEpSession;

PEP_STATUS init_transport_system(PEP_SESSION session, bool in_first);
void release_transport_system(PEP_SESSION session, bool out_last);

