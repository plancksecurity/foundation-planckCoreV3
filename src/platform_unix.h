// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef __APPLE__
#define _POSIX_C_SOURCE 200809L
#endif

#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/param.h>
#include <regex.h>

#ifndef ANDROID
#include <uuid/uuid.h>
#endif

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PEP_MAX_PATH 1024

PEP_STATUS unix_user_file_path(PEP_SESSION session, const char *fname, char **buffer);
PEP_STATUS unix_machine_file_path(PEP_SESSION session, const char *fname, char **buffer);

#ifdef NDEBUG
const char *gpg_conf(void);
const char *gpg_agent_conf(void);
const char *gpg_home(void);
#else
const char *gpg_conf(int reset);
const char *gpg_agent_conf(int reset);
const char *gpg_home(int reset);
#endif


#ifdef ANDROID

time_t timegm(struct tm* const t);

char *stpncpy(char *, const char *, size_t);
char *stpcpy(char *, const char *);

// Beware: predictable pseudo random with static seed!
// Only the lowest 31 bits are filled randomly.
//long int random(void);

const char *android_system_db(void);
#define SYSTEM_DB android_system_db()
#ifdef __APPLE__
#define LIBGPGME "libgpgme.11.dylib"
#else
#define LIBGPGME "libgpgme.so"
#endif

#elif __APPLE__
#include "TargetConditionals.h"
#include <string.h>
#if TARGET_OS_IPHONE

extern char* SystemDB;
#define SYSTEM_DB SystemDB
    
#endif
#endif

#if !defined(BSD) && !defined(__APPLE__)
size_t strlcpy(char* dst, const	char* src, size_t size);
size_t strlcat(char* dst, const	char* src, size_t size);

// N.B. This is ifdef'd out because NDK users sometimes have trouble finding regex functions in
//      the library in spite of the inclusion of regex.h - this is a FIXME, but since iOS is
//      *currently* the only netpgp user, we will ifdef this so that we don't block Android.
#ifdef USE_NETPGP
int regnexec(const regex_t* preg, const char* string,
             size_t len, size_t nmatch, regmatch_t pmatch[], int eflags);
#endif

#endif

#ifndef _UUID_STRING_T
#define _UUID_STRING_T
typedef char uuid_string_t[37];
#endif
#ifdef UUID
#undef UUID
#endif
// on *nix, uuid_t is an array and already implements pointer semantics
#define UUID uuid_t

#ifdef ANDROID
typedef char pEpUUID[16];
void uuid_generate_random(pEpUUID out);
void uuid_unparse_upper(pEpUUID uu, uuid_string_t out);
#else
typedef uuid_t pEpUUID;
#endif

#ifdef __cplusplus
}
#endif
