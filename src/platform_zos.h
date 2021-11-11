/**
 * @file    platform_zos.h
 * @brief   z/OS platform-specific implementation details
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_PLATFORM_ZOS_H
#define PEP_PLATFORM_ZOS_H

#if ! defined (ZOS)
# error "this header should only ever be included on z/OS"
#endif

// The compiler used by default on this platform does not support GNU-style
// attributes.
#include "platform_disable_attributes.h"

/* Workaround standard header problems. */

#ifdef __cplusplus
# undef _EXT
# define _NO_EXT
#endif
#include_next <stdlib.h>

#ifndef __cplusplus
char * stpcpy (char *dst, const char *src);
char * strndup (const char *s, size_t n);
size_t strnlen (const char *s, size_t maxlen);
#endif
#include <strings.h>

#include_next <string.h>


#endif // #ifndef PEP_PLATFORM_ZOS_H
