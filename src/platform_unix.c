/** 
 * @file platform_unix.c
 * @brief File description for doxygen missing. FIXME 
 * @license This file is under GNU General Public License 3.0. - see LICENSE.txt 
 */

#define _POSIX_C_SOURCE 200809L

#ifdef ANDROID
#ifndef __LP64__ 
#include <time64.h>
#endif
#endif

#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <glob.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <regex.h>

#include "platform_unix.h"
#include "dynamic_api.h"

#define MAX_PATH 1024
#ifndef LOCAL_DB_FILENAME
#define OLD_LOCAL_DB_FILENAME ".pEp_management.db"
#define OLD_KEYS_DB_FILENAME ".pEp_keys.db"
#define LOCAL_DB_FILENAME "management.db"
#define KEYS_DB_FILENAME "keys.db"
#endif
#define SYSTEM_DB_FILENAME "system.db"

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

char *strnstr(const char *big, const char *little, size_t len) {
    if (big == NULL || little == NULL)
        return NULL;
        
    if (*little == '\0')
        return (char*)big;
        
    const char* curr_big = big;
    
    size_t little_len = strlen(little);
    size_t remaining = len;

    const char* retval = NULL;
    
    for (remaining = len; remaining >= little_len && *curr_big != '\0'; remaining--, curr_big++) {
        // find first-char match
        if (*curr_big != *little) {
            continue;
        }
        retval = curr_big;

        const char* inner_big = retval + 1;
        const char* curr_little = little + 1;
        int j;
        for (j = 1; j < little_len; j++, inner_big++, curr_little++) {
            if (*inner_big != *curr_little) {
                retval = NULL;
                break;
            }    
        }
        if (retval)
            break;
    }
    return (char*)retval;
}


// #ifdef USE_NETPGP
// // FIXME: This may cause problems - this is a quick compatibility fix for netpgp code
// int regnexec(const regex_t* preg, const char* string,
//              size_t len, size_t nmatch, regmatch_t pmatch[], int eflags) {
//     return regexec(preg, string, nmatch, pmatch, eflags);
// }
// #endif

#endif

/**
 *  @internal
 *  
 *  <!--       _stradd()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    **first        char
 *  @param[in]    *second        constchar
 *  
 */
static char *_stradd(char **first, const char *second)
{
    assert(first && *first && second);
    if (!(first && *first && second))
        return NULL;

    size_t len1 = strlen(*first);
    size_t len2 = strlen(second);
    size_t size = len1 + len2 + 1;

    char *_first = realloc(*first, size);
    assert(_first);
    if (!_first)
        return NULL;
    *first = _first;

    strlcat(*first, second, size);
    return *first;
}

/**
 *  @internal
 *  
 *  <!--       _empty()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    **p        char
 *  
 */
static void _empty(char **p)
{
    free(*p);
    *p = NULL;
}

/**
 *  @internal
 *  
 *  <!--       _move()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *o        constchar
 *  @param[in]    *ext        constchar
 *  @param[in]    *n        constchar
 *  
 */
static void _move(const char *o, const char *ext, const char *n)
{
    assert(o && ext && n);
    if (!(o && ext && n))
        return;

    char *_old = strdup(o);
    assert(_old);
    if (!_old)
        return;

    char *r = _stradd(&_old, ext);
    if (!r) {
        free(_old);
        return;
    }

    char *_new = strdup(n);
    assert(_new);
    if (!_new) {
        free(_old);
        return;
    }

    r = _stradd(&_new, ext);
    if (r)
        rename(_old, _new);

    free(_old);
    free(_new);
}

#ifndef NDEBUG
static const char *_per_user_directory(int reset)
#else 
static const char *_per_user_directory(void)
#endif
{
    static char *path = NULL;

#ifdef NDEBUG    
    if (path)
        return path;
#else        
    if (path && !reset)
        return path;
    else if (path) {
        free(path);
        path = NULL;
    }
#endif    

    const char *home = NULL;
#ifndef NDEBUG
    home = getenv("PEP_HOME");
    if (!home)
#endif
    home = getenv("HOME");
    assert(home);
    if (!home)
        return NULL;

    path = strdup(home);
    assert(path);
    if (!path)
        return NULL;

    char *_path = _stradd(&path, "/");   
    if (!_path)
        goto error;

    _path = _stradd(&path, PER_USER_DIRECTORY);
    if (!_path)
        goto error;

    return path;

error:
    _empty(&path);
    return NULL;
}

#ifdef NDEBUG
const char *unix_local_db(void)
#else
const char *unix_local_db(int reset)
#endif
{
    static char *path = NULL;
#ifdef NDEBUG
    if (path)
#else
    if (path && !reset)
#endif
        return path;

    const char* pathret = NULL;
#ifndef NDEBUG 
    pathret = _per_user_directory(reset);
#else 
    pathret = _per_user_directory();
#endif

    if (!pathret)
        return NULL;

    path = strdup(pathret);
    assert(path);
    if (!path)
        return NULL;

    char *path_c = NULL;
    char *old_path = NULL;
    char *old_path_c = NULL;

    struct stat dir;
    int r = stat(path, &dir);
    if (r) {
        if (errno == ENOENT) {
            // directory does not yet exist
            r = mkdir(path, 0700);
            if (r)
                goto error;
        }
        else {
            goto error;
        }
    }

    char *_path = _stradd(&path, "/");   
    if (!_path)
        goto error;

    // make a copy of this path in case we need to move files
    path_c = strdup(path);
    assert(path_c);
    if (!path_c)
        goto error;

    _path = _stradd(&path, LOCAL_DB_FILENAME);
    if (!_path)
        goto error;

    struct stat file;
    r = stat(path, &file);
    if (r) {
        if (errno == ENOENT) {
            // we do not have management.db yet, let's test if we need to move
            // one with the old name
            const char *home = NULL;
#ifndef NDEBUG
            home = getenv("PEP_HOME");
            if (!home)
#endif
            home = getenv("HOME");
            // we were already checking for HOME existing, so this is only a
            // safeguard
            assert(home);

            old_path = strdup(home);
            assert(old_path);
            if (!old_path)
                goto error;

            char *_old_path = _stradd(&old_path, "/");   
            if (!_old_path)
                goto error;

            old_path_c = strdup(old_path);
            assert(old_path_c);
            if (!old_path_c)
                goto error;

            _old_path = _stradd(&old_path, OLD_LOCAL_DB_FILENAME);
            if (!_old_path)
                goto error;

            struct stat old;
            r = stat(old_path, &old);
            if (r == 0) {
                // old file existing, new file not yet existing, move
                rename(old_path, path);

                // if required move associated files, too
                _move(old_path, "-shm", path);
                _move(old_path, "-wal", path);

                // move keys database
                _old_path = _stradd(&old_path_c, OLD_KEYS_DB_FILENAME);
                if (!_old_path)
                    goto error;

                _path = _stradd(&path_c, KEYS_DB_FILENAME);
                if (!_path)
                    goto error;

                rename(old_path_c, path_c);

                // if required move associated files, too
                _move(old_path_c, "-shm", path_c);
                _move(old_path_c, "-wal", path_c);
            }
        }
        else {
            goto error;
        }
    }
    goto the_end;

error:
    _empty(&path);

the_end:
    free(path_c);
    free(old_path);
    free(old_path_c);
    return path;
}

DYNAMIC_API const char *per_user_directory(void) {
#ifdef NDEBUG
    return _per_user_directory();
#else 
    return _per_user_directory(false);
#endif
}

DYNAMIC_API const char *per_machine_directory(void)
{
    return PER_MACHINE_DIRECTORY;
}

const char *unix_system_db(void)
{
    static char *path = NULL;
    if (path)
        return path;

    path = strdup(per_machine_directory());
    assert(path);
    if (!path)
        return NULL;

    char *_path = _stradd(&path, "/");
    if (!_path)
        goto error;

    _path = _stradd(&path, SYSTEM_DB_FILENAME);
    if (!_path)
        goto error;

    return path;

error:
    _empty(&path);
    return NULL;
}
