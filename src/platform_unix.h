// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PLATFORM_UNIX_H
#define PLATFORM_UNIX_H

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

// pEp files and directories

#ifndef PER_USER_DIRECTORY
#define PER_USER_DIRECTORY ".pEp"
#endif

#ifndef PER_MACHINE_DIRECTORY
#if defined(__APPLE__) && !defined(TARGET_OS_IPHONE)
#define PER_MACHINE_DIRECTORY "/Library/Application Support/pEp"
#else
#define PER_MACHINE_DIRECTORY "/usr/local/share/pEp"
#endif
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifdef NDEBUG
const char *unix_local_db(void);
#else
const char *unix_local_db(int reset);
#endif
const char *unix_system_db(void);


#ifdef ANDROID

time_t timegm(struct tm* const t);

char *stpncpy(char *, const char *, size_t);
char *stpcpy(char *, const char *);

// Beware: predictable pseudo random with static seed!
// Only the lowest 31 bits are filled randomly.
//long int random(void);

const char *android_system_db(void);
#define SYSTEM_DB android_system_db()

#elif __APPLE__
#include "TargetConditionals.h"
#include <string.h>
    extern char* perMachineDirectory;
#define PER_MACHINE_DIRECTORY perMachineDirectory
    // It has been decided not to define PER_USER_DIRECTORY for iOS but HOME (which is defined by
    // the OS), at least temporarely.
#endif

#if !defined(BSD) && !defined(__APPLE__)
size_t strlcpy(char* dst, const	char* src, size_t size);
size_t strlcat(char* dst, const	char* src, size_t size);
char *strnstr(const char *big, const char *little, size_t len);

// N.B. This is ifdef'd out because NDK users sometimes have trouble finding regex functions in
//      the library in spite of the inclusion of regex.h - this is a FIXME, but since iOS is
//      *currently* the only netpgp user, we will ifdef this so that we don't block Android.
// #ifdef USE_NETPGP
// int regnexec(const regex_t* preg, const char* string,
//              size_t len, size_t nmatch, regmatch_t pmatch[], int eflags);
// #endif

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
#endif
