/**
 * @file    string_utilities.c
 * @brief   implementation of general-purpose string utilities, not part of
 *          the Engine API.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

/* For this compilation unit I want to disable function-entry log lines, which
   would be very frequent and very distracting. */
#define PEP_NO_LOG_FUNCTION_ENTRY 1

#include "string_utilities.h"

#include "pEp_internal.h"

#include <string.h>

PEP_STATUS append_string(PEP_SESSION session,
                         char **big_buffer_p,
                         size_t *big_buffer_used_size_p,
                         size_t *big_buffer_allocated_size_p,
                         const char *new_part)
{
    PEP_REQUIRE(session
                && big_buffer_p
                && big_buffer_used_size_p && big_buffer_allocated_size_p
                /* the new part is allowed to be an empty string or even NULL. */);

    /* Make sure that the buffer is actually non-NULL: we want a valid
       '\0'-terminated string at the end. */
    if (* big_buffer_p == NULL) {
        PEP_ASSERT(* big_buffer_used_size_p == 0);
        PEP_ASSERT(* big_buffer_allocated_size_p == 0);
        char *new_big_buffer = malloc(1);
        if (new_big_buffer == NULL)
            return PEP_OUT_OF_MEMORY;
        * big_buffer_p = new_big_buffer;
        new_big_buffer[0] = '\0';
        * big_buffer_allocated_size_p = 1;
    }
    /* From now on we can assume that the big buffer is '\0'-terminated.  By
       convention the '\0' terminator does not count towards the used size. */

    /* Ignore the empty-string case: in that case there is no need to do
       anything particular. */
    if (EMPTYSTR(new_part))
        return PEP_STATUS_OK;

    size_t new_part_length = strlen(new_part);
    /* Resize the buffer if needed. */
    size_t new_used_size = * big_buffer_used_size_p + new_part_length;
    if (new_used_size >= * big_buffer_allocated_size_p) {
        size_t new_allocated_size = ((* big_buffer_allocated_size_p * 2 )
                                     + new_part_length + /* '\0' */ 1);
        char *new_big_buffer = malloc(new_allocated_size);
        if (new_big_buffer == NULL)
            return PEP_OUT_OF_MEMORY;
        memcpy(new_big_buffer, * big_buffer_p, * big_buffer_used_size_p);
        free(* big_buffer_p);
        * big_buffer_p = new_big_buffer;
        * big_buffer_allocated_size_p = new_allocated_size;
    }
    strcpy((* big_buffer_p) + * big_buffer_used_size_p, new_part);
    * big_buffer_used_size_p = new_used_size;

    return PEP_STATUS_OK;
}
