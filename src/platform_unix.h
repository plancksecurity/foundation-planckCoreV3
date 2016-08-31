#ifndef __APPLE__
#define _POSIX_C_SOURCE 200809L
#endif

#include <unistd.h>
#include <strings.h>
#include <sys/select.h>
#include <regex.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *unix_local_db(void);

const char *gpg_conf(void);
const char *gpg_agent_conf(void);
const char *gpg_home(void);

#ifdef ANDROID

char *stpncpy(char *, const char *, size_t);
char *stpcpy(char *, const char *);

// Beware: predictable pseudo random with static seed!
// Only the lowest 31 bits are filled randomly.
long int random(void);

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

#ifdef __cplusplus
}
#endif
