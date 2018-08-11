// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once


#include "pEpEngine.h"


#ifdef __cplusplus
extern "C" {
#endif

// decode_sync_msg() - decode sync message from PER into XER
//
//  parameters:
//      data (in)               PER encoded data
//      size (in)               size of PER encoded data
//      text (out)              XER text of the same sync message

DYNAMIC_API PEP_STATUS decode_sync_msg(
        const char *data,
        size_t size,
        char **text
    );


// encode_sync_msg() - encode sync message from XER into PER
//
//  parameters:
//      text (in)               string with XER text of the sync message
//      data (out)              PER encoded data
//      size (out)              size of PER encoded data

DYNAMIC_API PEP_STATUS encode_sync_msg(
        const char *text,
        char **data,
        size_t *size
    );


#ifdef __cplusplus
}
#endif

