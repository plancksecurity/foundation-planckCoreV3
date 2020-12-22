// This file is under GNU General Public License 3.0
// see LICENSE.txt

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
