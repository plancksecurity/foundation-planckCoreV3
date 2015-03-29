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

const char *gpg_conf(void)
{
    static char buffer[MAX_PATH];
    static char dirname[MAX_PATH];
    static bool done = false;

    if (!done) {
        char *gpg_home = getenv("GNUPGHOME");
        if(gpg_home){

            char *p = stpncpy(buffer, gpg_home, MAX_PATH);
            size_t len = MAX_PATH - (p - buffer) - 2;
            if (len < strlen(gpg_conf_name))
            {
                assert(0);
                return NULL;
            }

            strncpy(dirname, buffer, MAX_PATH);
            *p++ = '/';
            strncpy(p, gpg_conf_name, len);

        }else{

            char *p = stpncpy(buffer, getenv("HOME"), MAX_PATH);
            size_t len = MAX_PATH - (p - buffer) - 3;

            if (len < strlen(gpg_conf_path) + strlen(gpg_conf_name))
            {
                assert(0);
                return NULL;
            }

            *p++ = '/';
            strncpy(p, gpg_conf_path, len);
            strncpy(dirname, buffer, MAX_PATH);
            p += strlen(gpg_conf_path);
            len -= strlen(gpg_conf_path) - 1;
            *p++ = '/';
            strncpy(p, gpg_conf_name, len);
        }

        if(access(buffer, F_OK)){ 
            int fd;
            if(access(dirname, F_OK )) { 
                mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR);
            }

            fd = open(buffer, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

            if(fd>0) {
                write(fd, gpg_conf_empty, strlen(gpg_conf_empty));
                close(fd);
            }
        }

        done = true;
    }
    return buffer;
}
