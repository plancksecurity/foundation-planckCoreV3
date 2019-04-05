// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "mime.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "etpan_mime.h"

static bool is_whitespace(char c)
{
    switch (c) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            return true;

        default:
            return false;
    }
}

DYNAMIC_API bool is_PGP_message_text(const char *text)
{
    if (text == NULL)
        return false;

    for (; *text && is_whitespace(*text); text++);

    return strncmp(text, "-----BEGIN PGP MESSAGE-----", 27) == 0;
}
