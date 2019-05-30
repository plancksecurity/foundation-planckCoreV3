// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define _POSIX_C_SOURCE 200809L

#ifdef ANDROID
#ifndef __LP64__ 
#include <time64.h>
#endif
#endif

#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>

#include "pEp_internal.h"
#include "platform_unix.h"

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

#ifdef ANDROID
#include <uuid.h>

/* FIXME : timegm will miss when linking for x86_64 on android, when supported */
#ifndef __LP64__ 
time_t timegm(struct tm* const t) {
    static const time_t kTimeMax = ~(1L << (sizeof(time_t) * CHAR_BIT - 1));
    static const time_t kTimeMin = (1L << (sizeof(time_t) * CHAR_BIT - 1));
    time64_t result = timegm64(t);
    if (result < kTimeMin || result > kTimeMax)
        return -1;
    return result;
}
#endif

char *stpncpy(char *dst, const char *src, size_t n)
{
    if (n != 0) {
        char *d = dst;
        const char *s = src;

        dst = &dst[n];
        do {
            if ((*d++ = *s++) == 0) {
                dst = d - 1;
                /* NUL pad the remaining n-1 bytes */
                while (--n != 0)
                    *d++ = 0;
                break;
            }
        } while (--n != 0);
    }
    return (dst);
}

char *stpcpy(char *dst, const char *src)
{
    for (;; ++dst, ++src) {
        *dst = *src;
        if (*dst == 0)
            break;
    }
    return dst;
}

/*
long int random(void)
{
    static bool seeded = false;
    static unsigned short xsubi[3];
    if(!seeded)
    {
        const long long t = (long long)time(NULL);
        xsubi[0] = (unsigned short)t;
        xsubi[1] = (unsigned short)(t>>16);
        xsubi[2] = (unsigned short)(t>>32);
        seeded = true;
    }

    return nrand48(xsubi);
} */

const char *android_system_db(void)
{
    static char buffer[PEP_MAX_PATH];
    static bool done = false;

    if (!done) {
        char *tw_env;
        if(tw_env = getenv("TRUSTWORDS")){
            char *p = stpncpy(buffer, tw_env, PEP_MAX_PATH);
            ssize_t len = PEP_MAX_PATH - (p - buffer) - 2;

            if (len < strlen(SYSTEM_DB_FILENAME)) {
                assert(0);
                return NULL;
            }

            *p++ = '/';
            strncpy(p, SYSTEM_DB_FILENAME, len);
            done = true;
        }else{
            return NULL;
        }

    }
    return buffer;
}


void uuid_generate_random(pEpUUID out)
{
    uuid_t *uuid;
    uuid_rc_t rc_create;
    size_t size = sizeof(uuid_string_t);
    void *_out = out;
	
    if ((rc_create = uuid_create(&uuid)) != UUID_RC_OK ||
        uuid_make(uuid, UUID_MAKE_V1) != UUID_RC_OK ||
        uuid_export(uuid, UUID_FMT_BIN, &_out, &size) != UUID_RC_OK)
    {
        memset(out, 0, sizeof(pEpUUID));
    }

    if (rc_create == UUID_RC_OK)
    {
        uuid_destroy(uuid);
    }
}


void uuid_unparse_upper(pEpUUID uu, uuid_string_t out)
{
    uuid_t *uuid;
    uuid_rc_t rc_create;
    size_t size = sizeof(uuid_string_t);
    void *_out = out;

    if ((rc_create = uuid_create(&uuid)) != UUID_RC_OK ||
        uuid_import(uuid, UUID_FMT_BIN, uu, sizeof(pEpUUID)) != UUID_RC_OK ||
        uuid_export(uuid, UUID_FMT_STR, &_out, &size) != UUID_RC_OK)
    {
        memset(out, 0, sizeof(uuid_string_t));
    }
    else 
    {
        out[sizeof(uuid_string_t) - 1] = 0;
    }

    if (rc_create == UUID_RC_OK)
    {
        uuid_destroy(uuid);
    }
}

#endif

PEP_STATUS unix_machine_file_path(PEP_SESSION session, const char *fname, char **path)
{
    assert(session);
    assert(fname);

    const char buffer[PEP_MAX_PATH];
    const char *s_dir = session->machine_directory;
    size_t f_len = strlen (fname);

    const char * const confvars[] = { NULL,   "PER_MACHINE_DIRECTORY", "TRUSTWORDS", "PEP_HOME", "PEPHOME", NULL,            "HOME",    NULL };
    const char * const confvals[] = { s_dir,   NULL,                   NULL,         NULL,       NULL,      SYSTEM_DB_PREFIX, NULL,     NULL };
    const char * const confsdir[] = { "/",     "/",                    "/",          "/",        "/",       "/",              "/.pEp/", NULL };
    const bool automkdir[]        = { false,   true,                   false,        true,       true,      false,            true,     false }; // use this on dirs only!
    const bool enforceifset[]     = { true,    false,                  true,         false,      false,     false,            false,    false };
    const bool deprecated[]       = { false,   false,                  true,         true,       true,      true,             true,     false };
    const char *home_env;
    int cf_i;
    char *p;

    for (cf_i = 0; confvars[cf_i] || confvals[cf_i] || confsdir[cf_i]; cf_i++) {
        if (((home_env = confvals[cf_i]) || (confvars[cf_i] && (home_env = getenv (confvars[cf_i])))) && (confsdir[cf_i])) {

            if (confvars[cf_i] && deprecated[cf_i]) {
                printf("%s: the environment variable '%s' is deprecated, please use PER_MACHINE_DIRECTORY instead.\n", fname, confvars[cf_i]);
            }

            p = stpncpy (buffer, home_env, PEP_MAX_PATH);
            ssize_t len = PEP_MAX_PATH - (p - buffer) - 2;

            if (len < f_len + strlen (confsdir[cf_i])) {
                assert(0);
                return PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
            }

            while (*(p-1) == '/' && (p-1) > buffer)   /* strip trailing slashes */
                p--;
            p = stpncpy (p, confsdir[cf_i], len);
            if (automkdir[cf_i]) {
                if (mkdir (buffer, S_IRUSR | S_IWUSR | S_IXUSR) != 0 && errno != EEXIST) {
                    perror (buffer);
                    return PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
                }
            }

            strncpy (p, fname, len);
            if (access (buffer, R_OK) == 0) {
                *path = strndup (buffer, PEP_MAX_PATH);
                if (!*path)
                    return PEP_OUT_OF_MEMORY;
                return PEP_STATUS_OK;
            }
            else if (enforceifset[cf_i]) {
                return PEP_INIT_CANNOT_OPEN_SYSTEM_DB;
            }
        }
    }
    return PEP_UNKNOWN_DB_ERROR;
}

#if !defined(BSD) && !defined(__APPLE__)

size_t strlcpy(char* dst, const	char* src, size_t size) {
    size_t retval = strlen(src);
    size_t size_to_copy = (retval < size ? retval : size - 1);
    
    // strlcpy doc says src and dst not allowed to overlap, as
    // it's undefined. So this is acceptable:
    memcpy((void*)dst, (void*)src, size_to_copy); // no defined error return, but strcpy doesn't either
    dst[size_to_copy] = '\0';
    return retval;
}

size_t strlcat(char* dst, const	char* src, size_t size) {
    size_t start_len = strnlen(dst, size);
    if (start_len == size)
        return size; // no copy, no null termination in size bytes, according to spec
    
    size_t add_len = strlen(src);
    size_t retval = start_len + add_len;
    size_t size_to_copy = (retval < size ? add_len : (size - start_len) - 1);
    
    // strlcat doc says src and dst not allowed to overlap, as
    // it's undefined. So this is acceptable:
    memcpy((void*)(dst + start_len), (void*)src, size_to_copy); // no defined error return, but strcpy doesn't either
    dst[start_len + size_to_copy] = '\0';
    return retval;
}

#ifdef USE_NETPGP
// FIXME: This may cause problems - this is a quick compatibility fix for netpgp code
int regnexec(const regex_t* preg, const char* string,
             size_t len, size_t nmatch, regmatch_t pmatch[], int eflags) {
    return regexec(preg, string, nmatch, pmatch, eflags);
}
#endif

#endif

PEP_STATUS unix_user_file_path(PEP_SESSION session, const char *fname, char **path)
{
    assert(session);
    assert(fname);

    const char buffer[PEP_MAX_PATH];
    const char *s_dir = session->user_directory;
    size_t f_len = strlen (fname);

    /* Note: in HOME, a dot and pEp_ is prepended to the file (~/.pEp_management.db, vs ~/.pEp/management.db) */
    const char * const confvars[] = { NULL,  "PER_USER_DIRECTORY", "PEP_HOME", "PEPHOME", "HOME",   "HOME",    NULL };
    const char * const confvals[] = { s_dir,  NULL,                 NULL,       NULL,      NULL,     NULL,     NULL };
    const char * const confsdir[] = { "/",    "/",                  "/",        "/",       "/.pEp_", "/.pEp/", NULL };
    const bool automkdir[]        = { false,  true,                 true,       true,      false,    true,     false }; // use this on dirs only!
    const bool enforceifset[]     = { true,   true,                 true,       true,      false,    true,     false };
    const bool deprecated[]       = { false,  false,                true,       true,      false,    false,    false };
    const char *home_env;
    int cf_i;
    ssize_t len;
    char *p;

    for (cf_i = 0; confvars[cf_i] || confvals[cf_i] || confsdir[cf_i]; cf_i++) {
        if (((home_env = confvals[cf_i]) || (confvars[cf_i] && (home_env = getenv (confvars[cf_i])))) && (confsdir[cf_i])) {

            if (confvars[cf_i] && deprecated[cf_i]) {
                printf("%s: the environment variable '%s' is deprecated, please use PER_USER_DIRECTORY instead.\n", fname, confvars[cf_i]);
            }

            p = stpncpy (buffer, home_env, PEP_MAX_PATH);
            len = PEP_MAX_PATH - (p - buffer) - 1;

            if (len < f_len + strlen (confsdir[cf_i])) {
                assert(0);
                return PEP_OUT_OF_MEMORY;
            }

            p = stpncpy(p, confsdir[cf_i], len);
            if (automkdir[cf_i]) {
                if (mkdir (buffer, S_IRUSR | S_IWUSR | S_IXUSR) != 0 && errno != EEXIST) {
                    perror (buffer);
                    return PEP_INIT_CANNOT_OPEN_DB;
                }
            }

            strncpy(p, fname, len);
            if (enforceifset[cf_i] || (access (buffer, R_OK) == 0)) {
                *path = strndup (buffer, PEP_MAX_PATH);
                if (!*path)
                    return PEP_OUT_OF_MEMORY;
                return PEP_STATUS_OK;
            }
        }
    }
    return PEP_UNKNOWN_DB_ERROR;
}

static const char *gpg_conf_path = ".gnupg";
static const char *gpg_conf_name = "gpg.conf";
static const char *gpg_agent_conf_name = "gpg-agent.conf";
static const char *gpg_conf_empty = "# Created by pEpEngine\n";

#ifdef NDEBUG
static bool ensure_gpg_home(const char **conf, const char **home){
#else
static bool ensure_gpg_home(const char **conf, const char **home, int reset){
#endif    
    static char path[MAX_PATH];
    static char dirname[MAX_PATH];
    static bool done = false;

#ifdef NDEBUG
    if (!done) {
#else
    if (reset || !done) {
#endif        
        char *p;
        ssize_t len;
        char *gpg_home_env = getenv("GNUPGHOME");
        char *home_env = getenv("HOME");

        if(gpg_home_env){

            p = stpncpy(path, gpg_home_env, MAX_PATH);
            len = MAX_PATH - (p - path) - 2;

            if (len < strlen(gpg_conf_name))
            {
                assert(0);
                return false;
            }

        }else if(home_env){

            p = stpncpy(path, home_env, MAX_PATH);
            len = MAX_PATH - (p - path) - 3;

            if (len < strlen(gpg_conf_path) + strlen(gpg_conf_name))
            {
                assert(0);
                return false;
            }

            *p++ = '/';
            strncpy(p, gpg_conf_path, len);
            p += strlen(gpg_conf_path);
            len -= strlen(gpg_conf_path) - 1;

        }else{

            assert(0);
            return false;
        }

        strncpy(dirname, path, MAX_PATH);
        *p++ = '/';
        strncpy(p, gpg_conf_name, len);

        if(access(path, F_OK)){ 
            int fd;
            if(access(dirname, F_OK )) { 
                mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR);
            }

            fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

            if(fd>0) {
                ssize_t res;
                len = strlen(gpg_conf_empty);
                res = write(fd, gpg_conf_empty, len);
                close(fd);
                if(res < len) {
                    assert(0);
                    return false;
                }
            }
        }

        done = true;
    }

    if(conf) *conf=path;
    if(home) *home=dirname;

    return true;
}

#ifdef NDEBUG
static bool ensure_gpg_agent_conf(const char **agent_conf){
#else
static bool ensure_gpg_agent_conf(const char **agent_conf, int reset){    
#endif    
    static char agent_path[MAX_PATH];
    static bool done = false;

#ifdef NDEBUG
    if (!done) {
        const char *dirname;

        if (!ensure_gpg_home(NULL, &dirname)) /* Then dirname won't be set. */
            return false;
#else
    if (reset || !done) {
        const char *dirname;

        if (!ensure_gpg_home(NULL, &dirname, reset)) /* Then dirname won't be set. */
            return false;
#endif

        char *p = stpncpy(agent_path, dirname, MAX_PATH);
        
        ssize_t len = MAX_PATH - (p - agent_path) - 2;

        if (len < strlen(gpg_agent_conf_name))
        {
            assert(0);
            return false;
        }

        *p++ = '/';
     
        strncpy(p, gpg_agent_conf_name, len);

        if(access(agent_path, F_OK)){ 
            int fd;
            if(access(dirname, F_OK )) { 
                mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR);
            }

            fd = open(agent_path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

            if(fd>0) {
                ssize_t res;
                len = strlen(gpg_conf_empty);
                res = write(fd, gpg_conf_empty, len);
                close(fd);
                if(res < len) {
                    assert(0);
                    return false;
                }
            }
        }
        done = true;
    }
    if(agent_conf) *agent_conf=agent_path;

    return true;
}

#ifdef NDEBUG
const char *gpg_conf(void)
{
    const char *conf;
    if(ensure_gpg_home(&conf, NULL))
        return conf;
    return NULL;
}
#else
const char *gpg_conf(int reset)
{
    const char *conf;
    if(ensure_gpg_home(&conf, NULL, reset))
        return conf;
    return NULL;
}
#endif

#ifdef NDEBUG
const char *gpg_home(void)
{
    const char *home;
    if(ensure_gpg_home(NULL, &home))
        return home;
    return NULL;
}
#else
const char *gpg_home(int reset)
{
    const char *home;
    if(ensure_gpg_home(NULL, &home, reset))
        return home;
    return NULL;
}
#endif

#ifdef NDEBUG
const char *gpg_agent_conf(void)
{
    const char *agent_conf;
    if(ensure_gpg_agent_conf(&agent_conf))
        return agent_conf;
    return NULL;
}
#else
const char *gpg_agent_conf(int reset)
{
    const char *agent_conf;
    if(ensure_gpg_agent_conf(&agent_conf, reset))
        return agent_conf;
    return NULL;
}
#endif

