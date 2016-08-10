#pragma once

// Windows platform specifica

#pragma warning(disable : 4996)

#include <Rpc.h>
#include <string.h>
#include <io.h>
#include <basetsd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ssize_t SSIZE_T
#define RTLD_LAZY 1
#define mode_t int

void *dlopen(const char *filename, int flag);
int dlclose(void *handle);
void *dlsym(void *handle, const char *symbol);
int mkstemp(char *templ);

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
char *stpcpy(char *dst, const char *src);

size_t strlcpy(char* dst, const	char* src, size_t size);
size_t strlcat(char* dst, const	char* src, size_t size);

const char *windoze_local_db(void);
const char *windoze_system_db(void);
const char *gpg_conf(void);

long random(void);

// on Windoze, uuid_t needs pointer semantics
typedef UUID *uuid_t;
#define _UUID_STRING_T
typedef char uuid_string_t[37];

void uuid_generate_random(uuid_t out);
int uuid_parse(char *in, uuid_t uu);
void uuid_unparse_upper(uuid_t uu, uuid_string_t out);

#ifndef inline
#define inline __inline
#endif

#ifdef __cplusplus
}
#endif
