/**
 * @file    mime.c
 * @brief   functionality as produced/consumed by the engine. This is the interface to the engine's
 *          use of the underlying MIME parser
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

/* In this compilation unit, like in others, functions do not take a session as
   a paramter; this prevents me from using the new debugging and logging
   functionalities.  I wonder if we should systematically add a session paramter
   to our functions, even when not needed, just for this.  --positron,
   2022-10 */

#define _EXPORT_PEP_ENGINE_DLL
#include "mime.h"
#include "pEp_internal.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

/**
 *  @internal
 *  
 *  <!--       is_whitespace()       -->
 *  
 *  @brief      checks if a character is a whitepsace character 
 *  
 *  @param[in]    c        char
 *  
 *  @return     bool    true if whitespace, false otherwise
 */
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
    if (EMPTYSTR(text))
        return false;

    for (; *text && is_whitespace(*text); text++);

    return strncmp(text, "-----BEGIN PGP MESSAGE-----", 27) == 0;
}
