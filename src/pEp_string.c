/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"
#include "pEp_string.h"

#include <stdlib.h>
#include <assert.h>

DYNAMIC_API char * new_string(const char *src, size_t len)
{
    char *s = NULL;
    if (src) {
        if (len)
            s = strndup(src, len);
        else
            s = strdup(src);
        assert(s);
    }
    else {
        s = calloc(1, len + 1);
        assert(s);
    }

    return s;
}


DYNAMIC_API void free_string(char *s)
{
    free(s);
}

DYNAMIC_API char * string_dup(const char *src, size_t len)
{
    assert(src);
    if (!src)
        return NULL;

    char *s = NULL;
    if (len)
        s = strndup(src, len);
    else
        s = strdup(src);
    assert(s);

    return s;
}

