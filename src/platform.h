#pragma once

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
