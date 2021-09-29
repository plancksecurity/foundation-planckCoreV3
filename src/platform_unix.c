/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef ZOS
#define _POSIX_C_SOURCE 200809L
#endif

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

#include "pEpEngine.h" /* For PEP_STATUS */
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

#ifndef strndup
char *strndup (const char *s, size_t n)
{
     char *result;
     size_t len = strnlen (s, n);

     result = (char *) malloc (len + 1);
     if (!result)
        return 0;

    result[len] = '\0';
    return (char *) memcpy (result, s, len);
}
#endif

#ifndef strnlen
size_t strnlen (const char *s, size_t maxlen)
{
    size_t i;

    for (i = 0; i < maxlen; ++i)
        if (s[i] == '\0')
            break;
    return i;
}
#endif

#ifndef stpcpy
char *stpcpy(char *dst, const char *src)
{
    for (;; ++dst, ++src) {
        *dst = *src;
        if (*dst == 0)
            break;
    }
    return dst;
}
#endif

#ifndef alloca
#pragma linkage(__alloca,builtin)
void *__alloca(unsigned long x);
void *alloca(unsigned long x)
{
    return __alloca(x);
}
#endif

#if defined(ANDROID) || defined(ZOS)
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

/* This is a non-caching function: see the comments in "Internal path caching
   functionality" below. */
static char *_android_system_db(void)
{
    char *buffer = malloc (MAX_PATH);
    if (buffer == NULL)
        return NULL;

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
    }else{
        return NULL;
    }
    return buffer;
}
#endif

#ifdef ZOS
char * e2as(const char * str)
{
    char *ret = (char *)malloc(strlen(str));
    strcpy(ret, str);
    __e2a_s(ret);
    return ret;
}

char * as2e(const char * str)
{
    char *ret = (char *)malloc(strlen(str));
    strcpy(ret, str);
    __a2e_s(ret);
    return ret;
}

void uuid_generate_random(pEpUUID out)
{
}

void uuid_unparse_upper(pEpUUID uu, uuid_string_t out)
{
}
#endif


#ifdef ANDROID
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

size_t strlcpy(char* dst, const char* src, size_t size) {
    size_t retval = strlen(src);
    size_t size_to_copy = (retval < size ? retval : size - 1);
    
    // strlcpy doc says src and dst not allowed to overlap, as
    // it's undefined. So this is acceptable:
    memcpy((void*)dst, (void*)src, size_to_copy); // no defined error return, but strcpy doesn't either
    dst[size_to_copy] = '\0';
    return retval;
}

size_t strlcat(char* dst, const char* src, size_t size) {
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

/**
 *  @internal
 *
 *  <!--       _strdup_or_NULL()       -->
 *
 *  @brief        Return a malloc-allocated copy of the given string, or (this
 *                is the added functionality with respect to the standard
 *                strdup) a malloc-allocated copy of "" if the argument is
 *                NULL.
 *                Return NULL only in case of an out-of-memory error.
 *
 *  @param[in]    *original constchar
 *  @retval       NULL      out of memory
 *  @retval       non-NULL  malloc-allocated buffer
 */
static char *_strdup_or_NULL(const char *original)
{
    if (original == NULL)
        original = "";
    return strdup (original);
}


/*
 * Environment variable expansion
 * **********************************************************************
 */

/* The state of a DFA implementing variable recognition in _expand_variables ,
   below. */
enum _expand_variable_state {
    _expand_variable_state_non_variable,
    _expand_variable_state_after_dollar,
    _expand_variable_state_after_backslash,
    _expand_variable_state_in_variable
};

/**
 *  @internal
 *
 *  <!--       _expand_variables()       -->
 *
 *  @brief        Set a malloc-allocated '\0'-terminated string which is
 *                a copy of the argument with shell variables expanded, where
 *                variable references use Unix shell-style syntax $VARIABLE.
 *                Notice that the alternative syntax ${VARIABLE} is not
 *                supported.
 *                See [FIXME: deployment-engineer documentation].
 *
 *  @param[in]    string_with_variables             char *
 *  @param[out]   copy_with_variables_expanded      char **
 *  @retval       PEP_STATUS_OK                     success
 *  @retval       PEP_UNBOUND_ENVIRONMENT_VARIABLE  unknown variable referenced
 *  @retval       PEP_PATH_SYNTAX_ERROR             invalid syntax in argument
 *  @retval       PEP_OUT_OF_MEMORY                 out of memory
 *
 */
static PEP_STATUS _expand_variables(char **out,
                                    const char *string_with_variables)
{
    PEP_STATUS res = PEP_STATUS_OK;
    size_t in_length = strlen(string_with_variables);
    const char *variable_name_beginning; /* This points within the input. */
    char *variable_name_copy = NULL /* we free on error. */;
    size_t allocated_size
#ifdef NDEBUG
        = 1024;
#else
        = 1 /* Notice that 0 is incorrect: this grows by doubling. */;
#endif // #ifdef NDEBUG
    int out_index = 0; /* The out index is also the used out size */
    const char *in = string_with_variables;
    /* In the pEp engine we adopt the convention of "" behaving the same as
       NULL.  Notice that we never free this, so it is not a problem if this
       string is not malloc-allocated. */
    if (in == NULL)
        in = "";
    /* We free on error. */
    * out = NULL ;

    /* Recognise a variable according to POSIX syntax which, luckily for us,
       only allows for letters, digits and underscores -- The first character
       may not be a digit... */
#define VALID_FIRST_CHARACTER_FOR_VARIABLE(c)  \
    (   ((c) >= 'a' && (c) <= 'z')             \
     || ((c) >= 'A' && (c) <= 'Z')             \
     || ((c) == '_'))
    /* ...But characters after the first may be. */
#define VALID_NON_FIRST_CHARACTER_FOR_VARIABLE(c)  \
    (   VALID_FIRST_CHARACTER_FOR_VARIABLE(c)      \
     || ((c) >= '0' && (c) <= '9'))

    /* Append the char argument to the result string, automatically resizing it
       if needed. */
#define EMIT_CHAR(c)                                      \
    do                                                    \
        {                                                 \
            if (out_index == allocated_size) {            \
                allocated_size *= 2;                      \
                /*fprintf (stderr, "ALLOCATED SIZE: %i -> %i\n", (int) allocated_size / 2, (int) allocated_size);*/\
                * out = realloc (* out, allocated_size);  \
                if (* out == NULL)                        \
                    FATAL (PEP_OUT_OF_MEMORY,             \
                           "cannot grow buffer");         \
            }                                             \
            (* out) [out_index] = (c);                    \
            out_index ++;                                 \
        }                                                 \
    while (false)

    /* Append the string argument to the output string, automatically resizing
       it as needed. */
#define EMIT_STRING(s)                      \
    do {                                    \
        const char *p;                      \
        for (p = (s); (* p) != '\0'; p ++)  \
            EMIT_CHAR (* p);                \
    } while (false)

    /* Emit the expansion of the environment variable whose name is delimited on
       the left by variable_name_beginning and on the right by the character
       coming right *before* in.  Fail fatally if the variable is unbound.
       The expansion is emitted by appending to the result string, automatically
       resizing it as needed. */
#define EMIT_CURRENT_VARIABLE                                      \
    do {                                                           \
        const char *variable_past_end = in;                        \
        size_t variable_name_length                                \
            = variable_past_end - variable_name_beginning;         \
        strcpy (variable_name_copy, variable_name_beginning);      \
        variable_name_copy [variable_name_length] = '\0';          \
        const char *variable_value = getenv (variable_name_copy);  \
        if (variable_value == NULL)                                \
            FATAL_NAME (PEP_UNBOUND_ENVIRONMENT_VARIABLE,          \
                        "unbound variable", variable_name_copy);   \
        EMIT_STRING (variable_value);                              \
    } while (false)

#define FATAL(code, message)                          \
    do { res = (code); goto failure; } while (false)
#define FATAL_NAME(code, message, name)               \
    FATAL((code), (message))

    /* We can allocate buffers, now that we have FATAL. */
    if ((variable_name_copy
         = malloc (in_length + 1 /* a safe upper bound for a sub-string. */))
        == NULL)
        FATAL (PEP_OUT_OF_MEMORY, "out of mmeory");
    if (((* out) = malloc (allocated_size)) == NULL)
        FATAL (PEP_OUT_OF_MEMORY, "out of memory");

    /* This logic implements a DFA. */
    enum _expand_variable_state s = _expand_variable_state_non_variable;
    char c;
    while (true) {
        c = * in;
        switch (s) {
        case _expand_variable_state_non_variable:
            if (c == '$') {
                variable_name_beginning = in + 1;
                s = _expand_variable_state_after_dollar;
            }
            else if (c == '\\')
                s = _expand_variable_state_after_backslash;
            else /* This includes c == '\0'. */
                EMIT_CHAR (c);
            if (c == '\0')
                goto success;
            break;

        case _expand_variable_state_after_backslash:
            if (c == '$' || c == '\\') {
                EMIT_CHAR (c);
                s = _expand_variable_state_non_variable;
            }
            else if (c == '\0') /* Just to give a nicer error message */
                FATAL (PEP_PATH_SYNTAX_ERROR, "trailing unescaped '\\'");
            else /* this would be correct even with '\0' */
                FATAL (PEP_PATH_SYNTAX_ERROR, "invalid escape");
            break;

        case _expand_variable_state_after_dollar:
            if (VALID_FIRST_CHARACTER_FOR_VARIABLE (c))
                s = _expand_variable_state_in_variable;
            else if (c == '\0') /* Just to give a nicer error message */
                FATAL (PEP_PATH_SYNTAX_ERROR,"trailing '$' character");
            else if (c == '\\') /* Just to give a nicer error message */
                FATAL (PEP_PATH_SYNTAX_ERROR,
                       "empty variable name followed by escape");
            else if (c == '$') /* Just to give a nicer error message */
                FATAL (PEP_PATH_SYNTAX_ERROR, "two consecutive '$' characters");
            else
                FATAL (PEP_PATH_SYNTAX_ERROR,
                       "invalid variable first character after '$'");
            break;

        case _expand_variable_state_in_variable:
            if (VALID_NON_FIRST_CHARACTER_FOR_VARIABLE (c))
                /* Do nothing */;
            else if (c == '\\') {
                EMIT_CURRENT_VARIABLE;
                s = _expand_variable_state_after_backslash;
            }
            else {
                /* This includes c == '\0'. */
                EMIT_CURRENT_VARIABLE;
                EMIT_CHAR (c);
                if (c == '\0')
                    goto success;
                else
                    s = _expand_variable_state_non_variable;
            }
            break;

        default:
            FATAL (PEP_STATEMACHINE_INVALID_STATE /* Slightly questionable: this
                                                     should be an assertion. */,
                   "impossible DFA state");
        } /* switch */

        in ++;
    } /* while */

 success:
    free(variable_name_copy);
    return res;

 failure:
    free(* out);
    * out = NULL;
    goto success;
#undef VALID_FIRST_CHARACTER_FOR_VARIABLE
#undef VALID_NON_FIRST_CHARACTER_FOR_VARIABLE
#undef EMIT_CHAR
#undef EMIT_STRING
#undef EMIT_CURRENT_VARIABLE
#undef FATAL
#undef FATAL_NAME
}


/*
 * Internal path caching functionality
 * **********************************************************************
 */

/* Several functions in this compilation unit return paths to files or
 * directories, always returning pointers to the same internally managed memory
 * at every call.
 *
 * The cache is filled at engine initialisation, using the value of environment
 * variables at initialisation time: after that point no out-of-memory errors
 * are possible, until reset.
 *
 * In debugging mode the cache can be "reset", with every path recomputed on
 * demand according to the current environment.
 */

/* For each path we define:
   - a static char * variable pointing to the cached value;
   - a prototype for a static function returning a malloc-allocated copy of
     the value, unexapanded, not using the cache (to be defined below by hand);
   - a public API function returning a pointer to cached memory. */
#define DEFINE_CACHED_PATH(name)                                       \
    /* A static variable holding the cached path, or NULL. */          \
    static char *_ ## name ## _cache = NULL;                           \
                                                                       \
    /* A prototype for the hand-written function returning the         \
       computed value for the path, without using the cache and        \
       without expanding variables. */                                 \
    static char *_ ## name(void);                                      \
                                                                       \
    /* The public version of the function, using the cache. */         \
    DYNAMIC_API const char *name(void)                                 \
    {                                                                  \
        if (_ ## name ## _cache == NULL) {                             \
            /* It is unusual and slightly bizarre than a path is       \
               accessed before initialisation; however it can happen   \
               in the engine test suite. */                            \
            fprintf (stderr,                                           \
                     "WARNING: accessing %s before its cache is set:"  \
                     " this should not happen in production.\n",       \
                     #name);                                           \
            reset_path_cache();                                        \
        }                                                              \
        assert (_ ## name ## _cache != NULL);                          \
        return _ ## name ## _cache;                                    \
    }

/* Define cached paths using the functionality above: */
DEFINE_CACHED_PATH (per_user_relative_directory)
DEFINE_CACHED_PATH (per_user_directory)
DEFINE_CACHED_PATH (per_machine_directory)
#ifdef ANDROID
    DEFINE_CACHED_PATH (android_system_db)
#endif
DEFINE_CACHED_PATH (unix_system_db)
DEFINE_CACHED_PATH (unix_local_db)

/* Free every cache variable and re-initialise it to NULL: this
   re-initialisation is important when this function is used here,
   internally, as part of cleanup on errors. */
DYNAMIC_API void clear_path_cache (void)
{
#define UNSET(name)                          \
    do {                                     \
        free((void *) _ ## name ## _cache);  \
        (_ ## name ## _cache) = NULL;        \
    } while (false)

    UNSET (per_user_relative_directory);
    UNSET (per_user_directory);
    UNSET (per_machine_directory);
#ifdef ANDROID
    UNSET (android_system_db);
#endif
    UNSET (unix_system_db);
    UNSET (unix_local_db);

#undef UNSET
}

DYNAMIC_API PEP_STATUS reset_path_cache(void)
{
    PEP_STATUS res = PEP_STATUS_OK;

#define SET_OR_FAIL(name)                                                 \
    do {                                                                  \
        unexpanded_path = (_ ## name)();                                  \
        if (unexpanded_path == NULL) {                                    \
            res = PEP_OUT_OF_MEMORY;                                      \
            goto free_everything_and_fail;                                \
        }                                                                 \
        res = _expand_variables(& _ ## name ## _cache, unexpanded_path);  \
        if (res != PEP_STATUS_OK)                                         \
            goto free_everything_and_fail;                                \
        /* Clear unxpanded_path for the next call of SET_OR_FAIL. */      \
        free((void *) unexpanded_path);                                   \
        unexpanded_path = NULL;                                           \
    } while (false)

    /* Start by releasing memory, which is needed in case this is not the first
       invocation. */
    clear_path_cache ();

    const char *unexpanded_path = NULL;

    SET_OR_FAIL (per_user_relative_directory);
    SET_OR_FAIL (per_user_directory);
    SET_OR_FAIL (per_machine_directory);
#ifdef ANDROID
    SET_OR_FAIL (android_system_db);
#endif
    SET_OR_FAIL (unix_system_db);
    SET_OR_FAIL (unix_local_db);

    return res;

 free_everything_and_fail:
    free((void *) unexpanded_path);
    clear_path_cache ();
    return res;

#undef SET_OR_FAIL
}


/**
 *  @internal
 *
 *  <!--       _per_user_directory()       -->
 *
 *  @brief            TODO
 *
 */
static char *_per_user_relative_directory(void)
{
    return _strdup_or_NULL(PER_USER_DIRECTORY);
}

/**
 *  @internal
 *  
 *  <!--       _per_user_directory()       -->
 *  
 *  @brief            TODO
 *  
 */
static char *_per_user_directory(void)
{
    char *path = NULL;

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

char *_unix_local_db(void)
{
    char* path = (char *) _per_user_directory() /* This memory is not shared. */;
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

static char *_per_machine_directory(void) {
    return _strdup_or_NULL(PER_MACHINE_DIRECTORY);
}

char *_unix_system_db(void)
{
    char *path = NULL;

    path = _per_machine_directory() /* Use this fresh copy. */;
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
