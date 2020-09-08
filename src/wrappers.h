/**
 * @file    wrappers.h
 * @brief   File maniupation wrappers
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#pragma once

#include "platform.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>

/**
 *  <!--       Fopen()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*filename		constchar
 *  @param[in]	*mode		constchar
 *  
 */
static inline FILE * Fopen(const char *filename, const char *mode)
{
    FILE * f;

    do {
        f = fopen(filename, mode);
    } while (f == NULL && errno == EINTR);

    return f;
}

/**
 *  <!--       Fdopen()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	fildes		int
 *  @param[in]	*mode		constchar
 *  
 */
static inline FILE * Fdopen(int fildes, const char *mode)
{
    FILE * f;

    do {
        f = fdopen(fildes, mode);
    } while (f == NULL && errno == EINTR);

    return f;
}

/**
 *  <!--       Fgets()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*str		char
 *  @param[in]	size		int
 *  @param[in]	*stream		FILE
 *  
 */
static inline char *Fgets(char * str, int size, FILE * stream)
{
    char * s;

    do {
        s = fgets(str, size, stream);
    } while (s == NULL && errno == EINTR);

    return s;
}

/**
 *  <!--       Fputs()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*str		constchar
 *  @param[in]	*stream		FILE
 *  
 */
static inline int Fputs(const char *str, FILE * stream)
{
    int r;

    do {
        r = fputs(str, stream);
    } while (r == EOF && errno == EINTR);

    return r;
}

/**
 *  <!--       Fclose()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*stream		FILE
 *  
 */
static inline int Fclose(FILE *stream)
{
    int r;

    do {
        r = fclose(stream);
    } while (r == EOF && errno == EINTR);

    return r;
}

/**
 *  <!--       Freopen()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*filename		constchar
 *  @param[in]	*mode		constchar
 *  @param[in]	*stream		FILE
 *  
 */
static inline FILE * Freopen(
        const char *filename,
        const char *mode,
        FILE * stream
    )
{
    FILE * f;

    do {
        f = freopen(filename, mode, stream);
    } while (f == NULL && errno == EINTR);

    return f;
}

static inline int Fprintf(FILE * stream, const char * format, ...)
{
    int n;
    va_list arglist;

    va_start(arglist, format);

    do {
        n = vfprintf(stream, format, arglist);
    } while (n < 0 && errno == EINTR);

    va_end( arglist );

    return n;
}

/**
 *  <!--       Fwrite()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*ptr		constvoid
 *  @param[in]	size		size_t
 *  @param[in]	nitems		size_t
 *  @param[in]	*stream		FILE
 *  
 */
static inline size_t Fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
{
    size_t r = 0;

    do {
        clearerr(stream);
        size_t n = fwrite((char *) ptr + r, size, nitems, stream);
        nitems -= n;
        r += n * size;
    } while (nitems && ferror(stream) == EINTR);

    return r;
}

/**
 *  <!--       Fread()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*ptr		void
 *  @param[in]	size		size_t
 *  @param[in]	nitems		size_t
 *  @param[in]	*stream		FILE
 *  
 */
static inline size_t Fread(void *ptr, size_t size, size_t nitems, FILE *stream)
{
    size_t r = 0;

    do {
        clearerr(stream);
        size_t n = fread((char *) ptr + r, size, nitems, stream);
        nitems -= n;
        r += n * size;
    } while (!feof(stream) && nitems && ferror(stream) == EINTR);

    return r;
}

/**
 *  <!--       Fflush()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*stream		FILE
 *  
 */
static inline int Fflush(FILE *stream)
{
    int r;

    do {
        r = fflush(stream);
    } while (r == -1 && errno == EINTR);

    return r;
}

/**
 *  <!--       Mkstemp()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	*template		char
 *  
 */
static inline int Mkstemp(char *template)
{
    int fd;

    do {
        fd = mkstemp(template);
    } while (fd == -1 && errno == EINTR);

    return fd;
}

/**
 *  <!--       Close()       -->
 *  
 *  @brief			TODO
 *  
 *  @param[in]	fildes		int
 *  
 */
static inline int Close(int fildes)
{
    int r;

    do {
        r = close(fildes);
    } while (r == -1 && errno == EINTR);

    return r;
}
