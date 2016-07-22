#define _POSIX_C_SOURCE 200809L

#include <unistd.h>
#include <strings.h>
#include <sys/select.h>

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

#ifndef BSD
#if !TARGET_OS_IPHONE
size_t strlcpy(char* dst, const	char* src, size_t size);
size_t strlcat(char* dst, const	char* src, size_t size);
#endif
#endif

#ifdef __cplusplus
}
#endif
