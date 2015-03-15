#pragma once

// Windows platform specifica

#pragma warning(disable : 4996)

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_LAZY 1

void *dlopen(const char *filename, int flag);
int dlclose(void *handle);
void *dlsym(void *handle, const char *symbol);

#ifndef strdup
#define strdup(A) _strdup((A))
#endif
#ifndef snprintf
#define snprintf(...) _snprintf(__VA_ARGS__)
#endif
#ifndef strtok_r
#define strtok_r(A, B, C) strtok_s((A), (B), (C))
#endif
#ifndef strncasecmp
#define strncasecmp(A, B, C) _strnicmp((A), (B), (C))
#endif
#ifndef gmtime_r
#define gmtime_r(A, B) gmtime_s((B), (A))
#endif

char *strndup(const char *s1, size_t n);

const char *windoze_local_db(void);
const char *windoze_system_db(void);
const char *gpg_conf(void);

long random(void);

#ifdef __cplusplus
}
#endif
