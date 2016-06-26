#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "platform_unix.h"

#define MAX_PATH 1024
#define LOCAL_DB_FILENAME ".pEp_management.db"
#define SYSTEM_DB_FILENAME "system.db"

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

#ifdef ANDROID
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

long int random(void)
{
    static unsigned short xsubi[3] = {'p', 'E', 'p'};
    return nrand48(xsubi);
}

const char *android_system_db(void)
{
    static char buffer[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *tw_env;
        if(tw_env = getenv("TRUSTWORDS")){
            char *p = stpncpy(buffer, tw_env, MAX_PATH);
            size_t len = MAX_PATH - (p - buffer) - 2;

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
#endif

const char *unix_local_db(void)
{
    static char buffer[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *home_env;
        if((home_env = getenv("HOME"))){
            char *p = stpncpy(buffer, home_env, MAX_PATH);
            size_t len = MAX_PATH - (p - buffer) - 2;

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
        size_t len;
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
                write(fd, gpg_conf_empty, strlen(gpg_conf_empty));
                close(fd);
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

        char *p;
        p = stpncpy(agent_path, dirname, MAX_PATH);
        
        size_t len = MAX_PATH - (p - agent_path) - 2;

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
                write(fd, gpg_conf_empty, strlen(gpg_conf_empty));
                close(fd);
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
