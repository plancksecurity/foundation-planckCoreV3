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

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

const char *unix_local_db(void)
{
    static char buffer[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *p = stpncpy(buffer, getenv("HOME"), MAX_PATH);
        size_t len = MAX_PATH - (p - buffer) - 2;

        if (len < strlen(LOCAL_DB_FILENAME)) {
            assert(0);
            return NULL;
        }

        *p++ = '/';
        strncpy(p, LOCAL_DB_FILENAME, len);
        done = true;
    }
    return buffer;
}

static const char *gpg_conf_path = ".gnupg";
static const char *gpg_conf_name = "gpg.conf";
static const char *gpg_conf_empty = "# Created by pEpEngine\n";

static bool ensure_gpg_home(const char **conf, const char **home){
    static char path[MAX_PATH];
    static char dirname[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *p;
        size_t len;
        char *gpg_home_env = getenv("GNUPGHOME");

        if(gpg_home_env){

            p = stpncpy(path, gpg_home_env, MAX_PATH);
            len = MAX_PATH - (p - path) - 2;

            if (len < strlen(gpg_conf_name))
            {
                assert(0);
                return false;
            }

        }else{

            p = stpncpy(path, getenv("HOME"), MAX_PATH);
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
