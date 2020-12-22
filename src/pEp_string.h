// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_STRING_H
#define PEP_STRING_H

#include <string.h>
#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


// new_string() - allocate a new string
//
//  parameters:
//      src (in)        string to copy or NULL
//      len (in)        length of newly created string or 0 for default
//
//  return value:
//      pointer to string object or NULL if out of memory
//
//  calling with str and len is equivalent to strndup()
//  calling with str but len=0 is equivalent to strdup()
//  calling with str=NULL is equivalent to calloc()

DYNAMIC_API char * new_string(const char *src, size_t len);


// free_string() - free memory occupied by string
//
//  parameters:
//      s (in)          pointer to string to free

DYNAMIC_API void free_string(char *s);


// string_dup() - duplicate a string
//
//  parameters:
//      src (in)        string to duplicate
//      len (in)        length of newly created string or 0 for default
//
//  return value:
//      pointer to copy or NULL if out of memory

DYNAMIC_API char * string_dup(const char *src, size_t len);


#ifdef __cplusplus
}
#endif

#endif
