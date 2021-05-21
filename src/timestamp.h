/**
 * @file    timestamp.h
 * @brief   timestamp creation, conversion, and manipulation functions
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

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


/**
 *  <!--       timegm_with_gmtoff()       -->
 *  
 *  @brief Convert the broken-out time into time_t, and respect tm_gmtoff
 *  
 *  @retval time_t that holds the usual "seconds since epoch"
 *  
 *  
 */
DYNAMIC_API time_t timegm_with_gmtoff(const timestamp* ts);


/**
 *  <!--       new_timestamp()       -->
 *  
 *  @brief Allocate a new timestamp
 *  
 *  @param[in]   clock    initial value or 0 if not available
 *  
 *  @retval pointer to timestamp object or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API timestamp * new_timestamp(time_t clock);


/**
 *  <!--       free_timestamp()       -->
 *  
 *  @brief Free memory occupied by timestamp
 *  
 *  @param[in]   ts    pointer to timestamp to free
 *  
 *  
 */

DYNAMIC_API void free_timestamp(timestamp *ts);


/**
 *  <!--       timestamp_dup()       -->
 *  
 *  @brief Duplicate a timestamp
 *  
 *  @param[in]   src    pointer to timestamp to duplicate
 *  
 *  @retval pointer to copy or NULL if out of memory
 *  
 *  
 */

DYNAMIC_API timestamp * timestamp_dup(const timestamp *src);


#ifdef __cplusplus
}
#endif

#endif
