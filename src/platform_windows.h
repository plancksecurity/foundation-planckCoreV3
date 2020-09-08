/**
 * @file    platform_windows.h
 * @brief   Windows platform-specific implementation details
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

// Windows platform specifica

#define _EXPORT_PEP_ENGINE_DLL
#pragma warning(disable : 4996)

// We need to make sure winsock2 is included before windows.h, or we will get redefinitions of symbols
// as windows.h includes winsock1.h, so we will have duplicate symbols if windows.h is included first.
// It seems some of our code includes sync.h before including winsock.h, leading to the failure.
// Including winsock2.h here fixes the problem for now...
#ifdef WIN32 
// winsock2.h includes windows.h and that leads to the definition of `min` and `max`
// which causes compile errors elsewhere.
#define NOMINMAX
#include <winsock2.h>
#endif // WIN32 

#include <Rpc.h>
#include <string.h>
#include <io.h>
#include <basetsd.h>
#include <time.h>
#include "timestamp.h"

// pEp files and directories

#ifndef PER_USER_DIRECTORY
#define PER_USER_DIRECTORY "%LOCALAPPDATA%\\pEp"
#endif

#ifndef PER_MACHINE_DIRECTORY
#define PER_MACHINE_DIRECTORY "%ALLUSERSPROFILE%\\pEp"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ssize_t SSIZE_T
#define RTLD_LAZY 1
#define mode_t int

#ifndef MIN
#define MIN(A, B) ((A)>(B) ? (B) : (A))
#define MAX(A, B) ((A)>(B) ? (A) : (B))
#endif

/**
 *  <!--       dlopen()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*filename		constchar
 *  @param[in]	flag		int
 *  
 */
void *dlopen(const char *filename, int flag);
/**
 *  <!--       dlclose()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*handle		void
 *  
 */
int dlclose(void *handle);
/**
 *  <!--       dlsym()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*handle		void
 *  @param[in]	*symbol		constchar
 *  
 */
void *dlsym(void *handle, const char *symbol);
/**
 *  <!--       mkstemp()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*templ		char
 *  
 */
int mkstemp(char *templ);

// Nota bene: It does _not_ respect timeptr->tm_gmtoff, so it behaves the same as its POSIX original.
//            Use timegm_with_gmtoff() from <pEp/timestamp.h> or that.
/**
 *  <!--       timegm()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*timeptr		timestamp
 *  
 */
DYNAMIC_API time_t timegm(timestamp *timeptr);

#ifndef strdup
#define strdup(A) _strdup((A))
#endif
#ifndef snprintf
#if _MSC_VER<1900 // Includes undefined case. This is a check for VS 2015, which throws an error.
#define snprintf(...) _snprintf(__VA_ARGS__)
#endif
#endif
#ifndef strtok_r
#define strtok_r(A, B, C) strtok_s((A), (B), (C))
#endif
#ifndef strncasecmp
#define strncasecmp(A, B, C) _strnicmp((A), (B), (C))
#endif
#ifndef strcasecmp
#define strcasecmp(A, B) _stricmp((A), (B))
#endif
#ifndef gmtime_r
#define gmtime_r(A, B) gmtime_s((B), (A))
#endif
#ifndef ftruncate
#define ftruncate(A, B) _chsize((A), (B))
#endif
#ifndef ftello
#define ftello(A) ((off_t) _ftelli64(A))
#endif

char *strndup(const char *s1, size_t n);
/**
 *  <!--       stpcpy()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*dst		char
 *  @param[in]	*src		constchar
 *  
 */
char *stpcpy(char *dst, const char *src);

/**
 *  <!--       strlcpy()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*dst		char
 *  @param[in]	*src		constchar
 *  @param[in]	size		size_t
 *  
 */
size_t strlcpy(char* dst, const	char* src, size_t size);
/**
 *  <!--       strlcat()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*dst		char
 *  @param[in]	*src		constchar
 *  @param[in]	size		size_t
 *  
 */
size_t strlcat(char* dst, const	char* src, size_t size);
/**
 *  <!--       strnstr()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*big		constchar
 *  @param[in]	*little		constchar
 *  @param[in]	len		size_t
 *  
 */
char *strnstr(const char *big, const char *little, size_t len);


/**
 *  <!--       windoze_keys_db()       -->
 *  
 *  @brief			TODO
 *  
 *  
 */
const char *windoze_keys_db(void);
/**
 *  <!--       windoze_local_db()       -->
 *  
 *  @brief			TODO
 *  
 *  
 */
const char *windoze_local_db(void);
/**
 *  <!--       windoze_system_db()       -->
 *  
 *  @brief			TODO
 *  
 *  
 */
const char *windoze_system_db(void);

/**
 *  <!--       log_output_debug()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*title		constchar
 *  @param[in]	*entity		constchar
 *  @param[in]	*description		constchar
 *  @param[in]	*comment		constchar
 *  
 */
void log_output_debug(const char *title, const char *entity, const char *description, const char *comment);

/**
 *  <!--       random()       -->
 *  
 *  @brief			TODO
 *  
 *  
 */
long random(void);

// on Windoze, uuid_t needs pointer semantics
typedef UUID pEpUUID[1];
#define _UUID_STRING_T
typedef char uuid_string_t[37];

/**
 *  <!--       uuid_generate_random()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	out		pEpUUID
 *  
 */
void uuid_generate_random(pEpUUID out);
/**
 *  <!--       uuid_parse()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*in		char
 *  @param[in]	uu		pEpUUID
 *  
 */
int uuid_parse(char *in, pEpUUID uu);
/**
 *  <!--       uuid_unparse_upper()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	uu		pEpUUID
 *  @param[in]	out		uuid_string_t
 *  
 */
void uuid_unparse_upper(pEpUUID uu, uuid_string_t out);

#ifndef __cplusplus
#define inline __inline
#endif

#ifdef __cplusplus
}
#endif
