// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once


#include "pEpEngine.h"


#ifdef __cplusplus
extern "C" {
#endif


struct Distribution;

// decode_Distribution_message() - decode PER encoded Distribution message
//
//  parameters:
//      data (in)               PER encoded data
//      size (in)               size of PER encoded data
//      msg (out)               Distribution message
//
//  caveat:
//      msg goes into the ownership of the caller

DYNAMIC_API PEP_STATUS decode_Distribution_message(
        const char *data,
        size_t size,
        struct Distribution **msg
    );


// encode_Distribution_message() - encode Distribution message into PER encoded data
//
//  parameters:
//      msg (in)                Distribution message
//      data (out)              PER encoded data
//      size (out)              size of PER encoded data
//
//  caveat:
//      data goes to the ownership of the caller

DYNAMIC_API PEP_STATUS encode_Distribution_message(
        struct Distribution *msg,
        char **data,
        size_t *size
    );


// PER_to_XER_Distribution_msg() - decode Distribution message from PER into XER
//
//  parameters:
//      data (in)               PER encoded data
//      size (in)               size of PER encoded data
//      text (out)              XER text of the same Distribution message

DYNAMIC_API PEP_STATUS PER_to_XER_Distribution_msg(
        const char *data,
        size_t size,
        char **text
    );


// XER_to_PER_Distribution_msg() - encode Distribution message from XER into PER
//
//  parameters:
//      text (in)               string with XER text of the Distribution message
//      data (out)              PER encoded data
//      size (out)              size of PER encoded data

DYNAMIC_API PEP_STATUS XER_to_PER_Distribution_msg(
        const char *text,
        char **data,
        size_t *size
    );


#ifdef __cplusplus
}
#endif

