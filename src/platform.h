// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include "platform_windows.h"
#else
#include "platform_unix.h"
#endif

/**
 *  <!--       pEp_fnmatch()       -->
 *
 *  @brief A portability wrapper meant to provide functionality equivalent to
 *         Unix fnmatch(3) with the default flags, on every platform.
 *         Return zero iff the string matches the pattern with Unix-style
 *         wildcards ("?" and "*").  This does not access the filesystem or
 *         check the existence of files.
 *
 *  @param[in]   pattern          the pattern including Unix-style wildcards
 *                                "?" and "*".
 *  @param[in]   string           the string being matched against the pattern.
 *
 *  @retval 0                     match
 *  @retval a non-zero value      no match
 *
 */
int pEp_fnmatch(const char *pattern, const char *string);

#ifdef __cplusplus
}
#endif

#endif
