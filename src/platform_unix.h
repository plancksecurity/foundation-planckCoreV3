// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef __APPLE__
#define _POSIX_C_SOURCE 200809L
#endif

#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <sys/select.h>
#include <regex.h>

#ifndef ANDROID
#include <uuid/uuid.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif

const char *unix_local_db(void);

const char *gpg_conf(void);
const char *gpg_agent_conf(void);
const char *gpg_home(void);

#ifdef ANDROID

time_t timegm(struct tm* const t);

char *stpncpy(char *, const char *, size_t);
char *stpcpy(char *, const char *);

// Beware: predictable pseudo random with static seed!
// Only the lowest 31 bits are filled randomly.
//long int random(void);

const char *android_system_db(void);
#define SYSTEM_DB android_system_db()
#define LIBGPGME "libgpgme.so"

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

#define platform_atomic_integer _Atomic volatile int
#define platform_atomic_increment(var) ++var
#define platform_atomic_decrement(var) --var

#ifdef __cplusplus
}
#endif
