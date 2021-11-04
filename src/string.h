#ifdef ZOS
#ifndef __cplusplus
char * stpcpy (char *dst, const char *src);
char * strndup (const char *s, size_t n);
size_t strnlen (const char *s, size_t maxlen);
#endif
#include <strings.h>
#endif

#include_next <string.h>
