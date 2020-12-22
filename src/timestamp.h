// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <time.h>
#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef WIN32
// this struct is compatible to struct tm
typedef struct _timestamp {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff; // offset from GMT in seconds
} timestamp;
#else
// for time values all functions are using POSIX struct tm
typedef struct tm timestamp;
#endif


// timegm_with_gmtoff() - convert the broken-out time into time_t, and respect tm_gmtoff
//
//  parameters:
//      timeptr(in)     broken-out time
//
//  return value:
//      time_t that holds the usual "seconds since epoch"
DYNAMIC_API time_t timegm_with_gmtoff(const timestamp* ts);


// new_timestamp() - allocate a new timestamp
//
//  parameters:
//      clock (in)      initial value or 0 if not available
//
//  return value:
//      pointer to timestamp object or NULL if out of memory

DYNAMIC_API timestamp * new_timestamp(time_t clock);


// free_timestamp() - free memory occupied by timestamp
//
//  parameters:
//      ts (in)         pointer to timestamp to free

DYNAMIC_API void free_timestamp(timestamp *ts);


// timestamp_dup() - duplicate a timestamp
//
//  parameters:
//      src (in)        pointer to timestamp to duplicate
//
//  return value:
//      pointer to copy or NULL if out of memory

DYNAMIC_API timestamp * timestamp_dup(const timestamp *src);


#ifdef __cplusplus
}
#endif

#endif
