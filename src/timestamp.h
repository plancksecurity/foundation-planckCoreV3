#pragma once

#include <time.h>
#include "dynamic_api.h"

#ifdef __cplusplus
extern "C" {
#endif


// for time values all functions are using POSIX struct tm

typedef struct tm timestamp;


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

