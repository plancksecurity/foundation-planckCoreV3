/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "pEp_internal.h"

#include "timestamp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


DYNAMIC_API time_t timegm_with_gmtoff(const timestamp* ts)
{
    time_t retval = -1;
    timestamp *_ts = NULL;

    if (ts) {
        _ts = timestamp_dup(ts);

        if (_ts) {
#if defined(__MVS__)
            const time_t raw_time = mktime(_ts);
            if (raw_time != -1) {
                retval = raw_time;
            }
#else
            const time_t raw_time = timegm(_ts);
            if (raw_time != -1) {
                retval = raw_time - _ts->tm_gmtoff;
            }
#endif
        }
    }

    free_timestamp(_ts); // Safe if NULL
    return retval;
}

DYNAMIC_API timestamp * new_timestamp(time_t clock)
{
    timestamp *ts = calloc(1, sizeof(timestamp));
    assert(ts);
    if (ts == NULL)
        return NULL;

    if (clock)
        gmtime_r(&clock, (struct tm *) ts);

    return ts;
}


DYNAMIC_API void free_timestamp(timestamp *ts)
{
    free(ts);
}

DYNAMIC_API timestamp * timestamp_dup(const timestamp *src)
{
    if (!src)
        return NULL;

    timestamp *dst = (timestamp *) malloc(sizeof(timestamp));
    memcpy(dst, src, sizeof(timestamp));

    return dst;
}
