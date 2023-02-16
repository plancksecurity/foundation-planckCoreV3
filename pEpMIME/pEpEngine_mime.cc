// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <assert.h>

#define _EXPORT_PEP_ENGINE_DLL
#include "../src/message.h"
#include "pEpMIME.hh"
#include "pEpMIME_internal.hh"

// function interface for pEp engine
// link this to use pEp MIME with C code

extern "C"
{
    DYNAMIC_API PEP_STATUS mime_decode_message(
            const char *mimetext,
            size_t size,
            message **msg,
            bool* has_possible_pEp_msg
        )
    {
        assert(msg);
        assert(mimetext);

        if (!(msg && mimetext))
            return PEP_ILLEGAL_VALUE;

        PEP_STATUS status = PEP_STATUS_OK;
        *msg = nullptr;

        try{
            message* m = pEpMIME::parse_message(mimetext, size, has_possible_pEp_msg);
            if(m)
            {
                *msg = m;
            }else{
                status = PEP_OUT_OF_MEMORY;
            }
        }catch(...)
        {
            status = PEP_UNKNOWN_ERROR;
        }
        return status;
    }


    PEP_STATUS mime_encode_message(
            const message * msg,
            bool omit_fields,
            char **mimetext,
            bool has_pEp_msg_attachment
        )
    {
        assert(msg);
        assert(mimetext);

        if (!(msg && mimetext))
            return PEP_ILLEGAL_VALUE;

        PEP_STATUS status = PEP_STATUS_OK;
        *mimetext = nullptr;

        try{
            char* t = pEpMIME::generate_message(msg, omit_fields, has_pEp_msg_attachment);
            if (t)
            {
                *mimetext = t;
            }else{
                status = PEP_OUT_OF_MEMORY;
            }
        }catch(...)
        {
            status = PEP_UNKNOWN_ERROR;
        }
        return status;
    }

} // extern "C"
