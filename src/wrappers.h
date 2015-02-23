#pragma once

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

static inline FILE * Fopen(const char *filename, const char *mode)
{
    FILE * f;

    do {
        f = fopen(filename, mode);
    } while (f == NULL && errno == EINTR);

    return f;
}

static inline char *Fgets(char * str, int size, FILE * stream)
{
    char * s;

    do {
        s = fgets(str, size, stream);
    } while (s == NULL && errno == EINTR);

    return s;
}

static inline int Fclose(FILE *stream)
{
    int r;

    do {
        r = fclose(stream);
    } while (r == -1 && errno == EINTR);

    return r;
}

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

static inline int Mkstemp(char *template)
{
    int fd;

    do {
        fd = mkstemp(template);
    } while (fd == -1 && errno == EINTR);

    return fd;
}

static inline FILE * Fdopen(int fildes, const char *mode)
{
    FILE * f;

    do {
        f = fdopen(fildes, mode);
    } while (f == NULL && errno == EINTR);

    return f;
}

static inline int Close(int fildes)
{
    int r;

    do {
        r = close(fildes);
    } while (r == -1 && errno == EINTR);

    return r;
}

static inline size_t Fread1(void *ptr, size_t size, FILE *stream)
{
    char *_buf = ptr;
    size_t rest = size;
    size_t bytes_read;

    for (bytes_read = 0; rest > 0; _buf += rest) {
        clearerr(stream);

        bytes_read = rest * fread(_buf, rest, 1, stream);
        rest -= bytes_read;

        if (ferror(stream) != 0 && ferror(stream) != EINTR)
            goto err_file;

        if (feof(stream))
            goto err_file;
    }

    return size;

err_file:
    return size - rest;
}

