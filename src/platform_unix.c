/** 
 * @file platform_unix.c
 * @brief File description for doxygen missing. FIXME 
 * @license This file is under GNU General Public License 3.0. - see LICENSE.txt 
 */

#ifndef __MVS__
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
#include <fnmatch.h>
#include <regex.h>

#include "pEpEngine.h" /* For PEP_STATUS */
#include "platform_unix.h"
#include "dynamic_api.h"

#define MAX_PATH 1024
#ifndef LOCAL_DB_FILENAME
#define OLD_LOCAL_DB_FILENAME ".pEp_management.db"
/* There is no old name for the log database, which was introduced long after
   the naming convention change. */
#define OLD_KEYS_DB_FILENAME ".pEp_keys.db"
#define LOCAL_DB_FILENAME "management.db"
#define LOG_DB_FILENAME "log.db"
#define KEYS_DB_FILENAME "keys.db"
#endif
#define SYSTEM_DB_FILENAME "system.db"

/* Here the definitions in pEp_internal.h are not visible. */
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')


/* Forward-declaration. */
static char *_per_user_directory(void);


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

#ifdef ANDROID
#include <uuid.h>
#endif
#if defined(ANDROID) || defined(__MVS__)
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

#ifdef __MVS__
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


/* String utilities
 * ***************************************************************** */

/* Return the concatenation of the two given strings, which must be
   non-empty, or NULL on error.  The result is malloc-allocated. */
static char *_string_concatenate_2(const char *a, const char *b)
{
    /* Sanity check. */
    assert(! EMPTYSTR(a) && ! EMPTYSTR(b));
    if (! (! EMPTYSTR(a) && ! EMPTYSTR(b)))
        return NULL;

    size_t total_length = strlen(a) + strlen(b);
    char *res = malloc(total_length + /* '\0' */ 1);
    if (res == NULL)
        goto end;
    sprintf(res, "%s%s", a, b);

 end:
    return res;
}

/* Like _string_concatenate_2, for three strings. */
static char *_string_concatenate_3(const char *a, const char *b, const char *c)
{
    /* Sanity check. */
    assert(! EMPTYSTR(a) && ! EMPTYSTR(b) && ! EMPTYSTR(c));
    if (! (! EMPTYSTR(a) && ! EMPTYSTR(b) && ! EMPTYSTR(c)))
        return NULL;

    char *a_b = _string_concatenate_2(a, b);
    if (a_b == NULL)
        return NULL;
    else
        return _string_concatenate_2(a_b, c);
}

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


/* File and directory utilities
 * ***************************************************************** */

/**
 *  @internal
 *  
 *  <!--       _home_directory()       -->
 *  
 *  @brief     Return the absolute pathname of the so-to-speak "home directory",
 *             which also takes into account the value of PEP_HOME for debugging
 *             builds.
 *  @retval    a non-empty string, not to be freed by the user   success
 *  @retval    NULL                                              any error
 */
static const char* _home_directory(void)
{
    const char *res;

#ifndef NDEBUG
    /* Only in debug mode we consider PEP_HOME... */
    res = getenv("PEP_HOME");

    /* ...But even in debug mode we fall back to HOME when PEP_HOME is undefined
       or empty. */
    if (EMPTYSTR(res))
#endif
    res = getenv("HOME");

    /* We should have found a result by now. */
    assert(! EMPTYSTR(res));
    if (EMPTYSTR(res))
        return NULL;
    return res;
}

/* A helper for _move_files_from_old_to_new_if_necessary. */
static PEP_STATUS _move_db_if_source_exists(const char *old_directory,
                                            const char *old_db_file,
                                            const char *new_directory,
                                            const char *new_db_file,
                                            bool *source_exists)
{
    /* Sanity check. */
    assert(! EMPTYSTR(old_directory) && ! EMPTYSTR(old_db_file)
           && ! EMPTYSTR(new_directory) && ! EMPTYSTR(new_db_file));
    if (! (! EMPTYSTR(old_directory) && ! EMPTYSTR(old_db_file)
           && ! EMPTYSTR(new_directory) && ! EMPTYSTR(new_db_file)))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

#define FAIL(new_status) do { status = (new_status); goto end; } while (false)

    /* Compose filenames. */
    char *old_pathname = _string_concatenate_3(old_directory, "/", old_db_file);
    char *new_pathname = _string_concatenate_3(new_directory, "/", new_db_file);
    if (old_pathname == NULL || new_pathname == NULL)
        FAIL(PEP_OUT_OF_MEMORY);

    /* Check if the source file exists. */
    struct stat stat_struct;
    int stat_result = stat(old_pathname, & stat_struct);
    if (stat_result != 0)
        switch (errno) {
        case ENOENT:
            /* The source does not exist, but this is not an error. */
            if (source_exists != NULL)
                * source_exists = false;
            goto end;
        default:
            FAIL(PEP_UNKNOWN_ERROR);
        }
    if (source_exists != NULL)
        * source_exists = true;

    /* Actually move the file. */
    int rename_result = rename(old_pathname, new_pathname);
    if (rename_result != 0)
        FAIL(PEP_CANNOT_CREATE_TEMP_FILE);

 end:
    free(old_pathname);
    free(new_pathname);
    return status;
#undef FAIL
}

/**
 *  @internal
 *  
 *  <!--       _move_files_from_old_to_new_if_necessary()       -->
 *  
 *  @brief     In case the old per-user files exists in the home directory
 *             move them to the new per-user directory; this also applies to
 *             "-shm" and "-wal" files.
 *             Assume the cache to be correctly set.
 *             Only return error status is moving is attempted but fails.
 */
static PEP_STATUS _move_files_from_old_to_new_if_necessary(void)
{
    PEP_STATUS status = PEP_STATUS_OK;
#define FAIL(new_status)  \
    do { status = (new_status); goto error; } while (false)
#define CHECK(expression)                \
    do {                                 \
        if (! (expression)) {            \
            status = PEP_UNKNOWN_ERROR;  \
            goto error;                  \
        }                                \
    } while (false)
#define CHECK_STATUS  \
    do { if (status != PEP_STATUS_OK) goto error; } while (false)

    const char *old_directory = _home_directory();
    const char *new_directory = _per_user_directory();
    char *old_file = NULL;
    CHECK(! EMPTYSTR(new_directory));

    bool source_existed;
#define MOVE(old_file, new_file) /* old_file and new_file must be literals */   \
    do {                                                                        \
        status                                                                  \
            = _move_db_if_source_exists(old_directory, old_file,                \
                                        new_directory, new_file,                \
                                        & source_existed);                      \
        CHECK_STATUS;                                                           \
        if (source_existed) {                                                   \
            status = _move_db_if_source_exists(old_directory,                   \
                                               old_file "-shm",                 \
                                               new_directory,                   \
                                               new_file "-shm",                 \
                                               NULL);                           \
            CHECK_STATUS;                                                       \
            status = _move_db_if_source_exists(old_directory,                   \
                                               old_file "-wal",                 \
                                               new_directory,                   \
                                               new_file "-wal",                 \
                                               NULL);                           \
            CHECK_STATUS;                                                       \
        }                                                                       \
    } while (false)

    /* Move the local database and the key database. */
    MOVE(OLD_LOCAL_DB_FILENAME, LOCAL_DB_FILENAME);
    MOVE(OLD_KEYS_DB_FILENAME, KEYS_DB_FILENAME);
    /* No need to do the same for the debug database, which has never been in
       the old directory. */

#undef FAIL
#undef CHECK
#undef CHECK_STATUS
#undef MOVE
    return status;

 error:
    free(old_file);
    return status;
}


/* Directory creation
 * ***************************************************************** */

/* Make a directory unless it exists already, and make sure it has the correct
   owner and permissions.  Return error state only if it was not possible to fix
   the existing state.  Fail if the path exists as a non-directory. */
static PEP_STATUS _mkdir(const char *directory_path)
{
    /* Make sure the directory exists and has the correct attributes. */
    struct stat stat_struct;
    int stat_result = stat(directory_path, & stat_struct);
    if (stat_result != 0)
        switch (errno) {
        case ENOENT:
            {
                /* The directory does not exist.  Make it. */
                int mkdir_result = mkdir(directory_path,
                                         /* u+rwx, nothing else */ 0700);
                if (mkdir_result != 0)
                    return PEP_CANNOT_CREATE_TEMP_FILE;
                else
                    return PEP_STATUS_OK;
            }
        default:
            return PEP_UNKNOWN_ERROR;
        }

    /* If we arrived here some filesystem object with the given path existed
       already. */
    if (stat_struct.st_uid != getuid())
        /* Existing filesystem object but wrong owner. */
        return PEP_CANNOT_CREATE_TEMP_FILE;
    if (! S_ISDIR(stat_struct.st_mode))
        /* Existing filesystem object but not a directory. */
        return PEP_CANNOT_CREATE_TEMP_FILE;
    else if (   ! (stat_struct.st_mode & S_IRUSR)
             || ! (stat_struct.st_mode & S_IWUSR)
             || ! (stat_struct.st_mode & S_IXUSR)
             ||   (stat_struct.st_mode & S_IRGRP)
             ||   (stat_struct.st_mode & S_IWGRP)
             ||   (stat_struct.st_mode & S_IXGRP)
             ||   (stat_struct.st_mode & S_IROTH)
             ||   (stat_struct.st_mode & S_IWOTH)
             ||   (stat_struct.st_mode & S_IXOTH))
        /* Existing directory but wrong permissions: fix them. */
        {
            int chmod_result = chmod(directory_path,
                                     /* u+rwx, nothing else */ 0700);
            if (chmod_result != 0)
                return PEP_CANNOT_CREATE_TEMP_FILE;
        }

    /* If we arrived here the directory already existed and everything is
       right. */
    return PEP_STATUS_OK;
}


/* Environment variable expansion
 * ***************************************************************** */

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
 *  @param[out]   out                               char** copy with variables expanded 
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
    variable_name_beginning = NULL; /* Just to silence a GCC warning. */
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


/* Internal path caching functionality
 * ***************************************************************** */

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
               accessed before initialisation; however it can happen,  \
               for example in the engine test suite. */                \
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
DEFINE_CACHED_PATH (unix_log_db)

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
    UNSET (unix_log_db);

#undef UNSET
}

DYNAMIC_API PEP_STATUS reset_path_cache(void)
{
    PEP_STATUS res = PEP_STATUS_OK;

#define GOTO_ON_ERROR                       \
    do {                                    \
        if (res != PEP_STATUS_OK)           \
            goto free_everything_and_fail;  \
    } while (false)

#define SET_OR_FAIL(name)                                                 \
    do {                                                                  \
        unexpanded_path = (_ ## name)();                                  \
        if (unexpanded_path == NULL) {                                    \
            res = PEP_OUT_OF_MEMORY;                                      \
            goto free_everything_and_fail;                                \
        }                                                                 \
        res = _expand_variables(& _ ## name ## _cache, unexpanded_path);  \
        GOTO_ON_ERROR;                                                    \
        /* Clear unxpanded_path for the next call of SET_OR_FAIL. */      \
        free((void *) unexpanded_path);                                   \
        unexpanded_path = NULL;                                           \
    } while (false)

    /* Start by releasing memory, which is needed in case this is not the first
       invocation. */
    clear_path_cache ();

    const char *unexpanded_path = NULL;

    /* Compute paths. */
    SET_OR_FAIL(per_user_relative_directory);
    SET_OR_FAIL(per_user_directory);
    SET_OR_FAIL(per_machine_directory);
#ifdef ANDROID
    SET_OR_FAIL(android_system_db);
#endif
    SET_OR_FAIL(unix_system_db);
    SET_OR_FAIL(unix_local_db);
    SET_OR_FAIL(unix_log_db);

    /* At this point each global string variable contains an already expanded
       path name. */

    /* Make the per-user directory (the per system directory has already been
       made at installation time, and we will notice problems when trying to
       open the system database).  The per-user directory is used for both the
       "local database" management.db and for the logging database log.db . */
    res = _mkdir(_per_user_directory_cache);
    GOTO_ON_ERROR;

    /* Move from old paths to new paths. */
    res = _move_files_from_old_to_new_if_necessary();
    GOTO_ON_ERROR;

    return res;

 free_everything_and_fail:
    free((void *) unexpanded_path);
    clear_path_cache ();
    return res;

#undef SET_OR_FAIL
#undef GOTO_ON_ERROR
}


/**
 *  @internal
 *
 *  <!--       _per_user_relative_directory()       -->
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

    const char *home = _home_directory();
    assert(! EMPTYSTR(home));
    if (EMPTYSTR(home))
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

/* Compute the path, without touching the actual filesystem.  Notice that
   variables still need to be expanded ...*/
static char *_unix_local_db(void)
{
    return _string_concatenate_3(_per_user_directory(), "/", LOCAL_DB_FILENAME);
}

/* Like _unix_local_db for the log database: compute the path, without touching
   the actual filesystem.  No need to make sure here that the directory exists;
   notice that variables still need to be expanded ...*/
static char *_unix_log_db(void)
{
    return _string_concatenate_3(_per_user_directory(), "/", LOG_DB_FILENAME);
}

static char *_per_machine_directory(void) {
    return _strdup_or_NULL(PER_MACHINE_DIRECTORY);
}

static char *_unix_system_db(void)
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


/* Library functions
 * ***************************************************************** */

int pEp_fnmatch(const char *pattern, const char *string)
{
    /* The implementation is completely trivial on Unix. */
    return fnmatch(pattern, string,
                   /* No FNM_FILE_NAME;
                      no FNM_PERIOD;
                      no FNM_NOESCAPE. */
                   0);
}

void pEp_sleep_ms(unsigned long ms)
{
    /* Convert the one-dimentional number of milliseconds into the required
       struct. */
    struct timespec sleep_time;
    sleep_time.tv_sec = (int) (ms / 1000);
    sleep_time.tv_nsec = (long) (ms % 1000L) * 1000000L;

    /* Wait, using a loop to make sure that if we are interrupted early we do
       not sleep too little. */
    int nanosleep_result;
    struct timespec remaining;
    do {
        nanosleep_result = nanosleep(& sleep_time, & remaining);
        if (nanosleep_result != 0) {
            assert(errno != EINVAL);
            sleep_time = remaining;
        }
    } while (nanosleep_result != 0);
}
