/**
 * @file     platform.h
 * @brief    Checks platform values and causes the appropriate platform-specific header to be included
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Right now z/OS is not mutually exclusive with the other platforms: the way we
   use it, it is a flavour of Unix... */
#if defined (ZOS)
# include "platform_zos.h"
#endif

/* ...However the other platforms are indeed mutually exclusive, for the
   purposes of the platform_* files in the engine. */
#if defined (UNIX)
# include "platform_unix.h"
#elif defined (_WIN32)
# include "platform_windows.h"
#else
  /* Unix is the default: this is useful for installed headers. */
# include "platform_unix.h"
#endif

#ifdef __cplusplus
}
#endif

#endif
