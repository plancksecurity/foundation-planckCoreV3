// This file is under GNU General Public License 3.0
// see LICENSE.txt

#define _POSIX_C_SOURCE 200809L

#ifdef ANDROID
#ifndef __LP64__ 
#include <time64.h>
#endif
#endif

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <regex.h>

#include "platform_unix.h"

#define MAX_PATH 1024
#ifndef LOCAL_DB_FILENAME
#define LOCAL_DB_FILENAME ".pEp_management.db"
#endif
#define SYSTEM_DB_FILENAME "system.db"

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
    static char buffer[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *tw_env;
        if(tw_env = getenv("TRUSTWORDS")){
            char *p = stpncpy(buffer, tw_env, MAX_PATH);
            ssize_t len = MAX_PATH - (p - buffer) - 2;

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

const char *unix_local_db(void)
{
    static char buffer[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *home_env;
        if((home_env = getenv("HOME"))){
            char *p = stpncpy(buffer, home_env, MAX_PATH);
            ssize_t len = MAX_PATH - (p - buffer) - 2;

            if (len < strlen(LOCAL_DB_FILENAME)) {
                assert(0);
                return NULL;
            }

            *p++ = '/';
            strncpy(p, LOCAL_DB_FILENAME, len);
            done = true;
        }else{
            return NULL;
        }

    }
    return buffer;
}

static const char *gpg_conf_path = ".gnupg";
static const char *gpg_conf_name = "gpg.conf";
static const char *gpg_agent_conf_name = "gpg-agent.conf";
static const char *gpg_conf_empty = "# Created by pEpEngine\n";

static bool ensure_gpg_home(const char **conf, const char **home){
    static char path[MAX_PATH];
    static char dirname[MAX_PATH];
    static bool done = false;

    if (!done) {
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

static bool ensure_gpg_agent_conf(const char **agent_conf){
    static char agent_path[MAX_PATH];
    static bool done = false;

    if (!done) {
        const char *dirname;

        if (!ensure_gpg_home(NULL, &dirname)) /* Then dirname won't be set. */
            return false;

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

const char *gpg_conf(void)
{
    const char *conf;
    if(ensure_gpg_home(&conf, NULL))
        return conf;
    return NULL;
}

const char *gpg_home(void)
{
    const char *home;
    if(ensure_gpg_home(NULL, &home))
        return home;
    return NULL;
}

const char *gpg_agent_conf(void)
{
    const char *agent_conf;
    if(ensure_gpg_agent_conf(&agent_conf))
        return agent_conf;
    return NULL;
}
