/**
 * @file    platform_unix.h
 * @brief   UNIX platform-specific implementation details
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PLATFORM_UNIX_H
#define PLATFORM_UNIX_H

#if !defined(__APPLE__) && !defined(__MVS__)
#define _POSIX_C_SOURCE 200809L
#endif

#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <sys/select.h>
#ifndef __MVS__
#include <sys/param.h>
#endif
#include <regex.h>

#ifdef __MVS__
char * e2as(const char * str);
char * as2e(const char * str);
#endif

#if defined(ANDROID)
#elif defined(__MVS__)
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
#endif

/* In the logging filesystem we use getpid, which apparently is not available in
   the windows API; for that reason we simulate it in platform_windows.[ch].
   Anyway we want pid_t and getpid to be unconditionally available -- hence
   these #include lines. */
#include <sys/types.h>
#include <unistd.h>

#ifndef MIN
#define MIN(A, B) ((A)>(B) ? (B) : (A))
#endif

#ifndef MAX
#define MAX(A, B) ((A)>(B) ? (A) : (B))
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

/**
 *  <!--       unix_local_db()       -->
 *  
 *  @brief      Return an absolute path to the local database, with Unix
 *              variables already expanded, making sure that the directory
 *              exists.
 *  		The returned pointed refers memory managed by
 *  		the engine, which will remain valid until
 *  		the next call to reset_path_cache.
 *  
 */
const char *unix_local_db(void);

/**
 *  <!--       unix_log_db()       -->
 *  
 *  @brief      Like unix_local_db, but for the log database.
 *  
 */
const char *unix_log_db(void);

/**
 *  <!--       unix_system_db()       -->
 *  
 *  @brief      Like unix_local_db and unix_log_db, but for the system database.
 *              Notice that the system database is read-only, and shared by
 *              multiple Unix users.
 *  
 */
const char *unix_system_db(void);


#ifdef ANDROID

time_t timegm(struct tm* const t);

char *stpncpy(char *, const char *, size_t);
char *stpcpy(char *, const char *);

// Beware: predictable pseudo random with static seed!
// Only the lowest 31 bits are filled randomly.
//long int random(void);

/*
 *  <!--   android_system_db()       -->
 *
 *  @brief            TODO
 *
 *  		The returned pointed refers memory managed by
 *  		the engine, which will remain valid until
 *  		the next call to reset_path_cache.
 */
const char *android_system_db(void);
#define SYSTEM_DB android_system_db()

#elif __APPLE__
#include "TargetConditionals.h"
#include <string.h>
#if TARGET_OS_IPHONE //read as `if iOS`
    extern char* perMachineDirectory;
#define PER_MACHINE_DIRECTORY perMachineDirectory
    // It has been decided not to define PER_USER_DIRECTORY for iOS but HOME (which is defined by
    // the OS), at least temporarely.
#endif
#endif

#if !defined(BSD) && !defined(__APPLE__)
/**
 *  <!--       strlcpy()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  dst         char*
 *  @param[in]  src         const char*
 *  @param[in]  size        size_t
 *  
 */
size_t strlcpy(char* dst, const    char* src, size_t size);
/**
 *  <!--       strlcat()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  dst         char*
 *  @param[in]  src         const char*
 *  @param[in]  size        size_t
 *  
 */
size_t strlcat(char* dst, const    char* src, size_t size);
/**
 *  <!--       strnstr()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  big        const char*
 *  @param[in]  little     const char*
 *  @param[in]  len        size_t
 *  
 */
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

#if defined(ANDROID) || defined(__MVS__)
typedef char pEpUUID[16];
void uuid_generate_random(pEpUUID out);
void uuid_unparse_upper(pEpUUID uu, uuid_string_t out);
#else
typedef uuid_t pEpUUID;
#endif


/* Feature macros
 * ***************************************************************** */

/* We can write to stdout and stderr. */
#define PEP_HAVE_STDOUT_AND_STDERR  1

/* We can use the syslog facility. */
#define PEP_HAVE_SYSLOG  1

/* We have the Android log if this is Android. */
#if defined(ANDROID)
#   define PEP_HAVE_ANDROID_LOG  1
#endif

/* We do not have the windows log. */
/* #undef PEP_HAVE_WINDOWS_LOG */

/* Using any compiler we support on these platforms we can use GNU C's extension
   __PRETTY_FUNCTION__ : same idea as __func__, but the expansion shows classes
   and namespaces in C++. */
#define PEP_HAVE_PRETTY_FUNCTION  1

#ifdef __cplusplus
}
#endif
#endif
