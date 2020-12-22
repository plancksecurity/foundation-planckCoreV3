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

#ifdef WIN32
#include "platform_windows.h"
#else
#include "platform_unix.h"
#endif

#ifdef __cplusplus
}
#endif

#endif
