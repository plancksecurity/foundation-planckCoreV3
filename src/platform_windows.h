#pragma once

// Windows platform specifica

#define RTLD_LAZY 1
#ifndef strdup
#define strdup _strdup
#endif
#ifndef snprintf
#define snprintf _snprintf
#endif
#pragma warning(disable : 4996)

#ifdef __cplusplus
extern "C" {
#endif

void *dlopen(const char *filename, int flag);
int dlclose(void *handle);
void *dlsym(void *handle, const char *symbol);

char *strtok_r(
        char *restrict str,
        const char *restrict sep,
        char **restrict lasts
    );

const char *windoze_local_db(void);
const char *windoze_system_db(void);
const char *gpg_conf(void);

long random(void);

#ifdef __cplusplus
}
#endif
