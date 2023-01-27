/**
 * @file    pEp_debug.c
 * @brief   pEp Engine debugging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#define _EXPORT_PEP_ENGINE_DLL
#include "pEp_debug.h"

#include <stdlib.h>


/* Internal functions.
 * ***************************************************************** */

DYNAMIC_API void pEp_abort_unless_PEP_NOABORT(void)
{
    if (getenv("PEP_NOABORT") == NULL)
        abort();

    /* Otherwise there is no need to print anything; calls to this function
       always come after logging. */
}
