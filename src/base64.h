/** @file */
/** @brief File description for doxygen missing. FIXME */

// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "dynamic_api.h"
#include "bloblist.h"

#ifdef __cplusplus
extern "C" {
#endif

bloblist_t* base64_str_to_binary_blob(const char* input, int length);

#ifdef __cplusplus
}
#endif
