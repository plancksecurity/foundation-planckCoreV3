#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "mailmime.h"
#include "mailmime.leg.c.src"
#include "pEpEngine.h"

DYNAMIC_API PEP_STATUS parse_mailmessage(const char *mimetext,
                         message **msg) {
    PEP_STATUS status = PEP_STATUS_OK;
    message *_msg = NULL;
    
    assert(mimetext);
    assert(msg);
    
    if (!(mimetext && msg))
        return PEP_ILLEGAL_VALUE;
    
    *msg = NULL;
 
    _msg = new_message(PEP_dir_incoming);
    
    yycontext ctx;
    memset(&ctx, 0, sizeof(yycontext));
    ctx.input_str = mimetext;
    ctx.index_consumed = 0;
    ctx.parsed_msg = new_message(PEP_dir_incoming);
    ctx.parsed_msg->opt_fields = new_stringpair_list(NULL);
    ctx.curr_address_list = NULL;
    ctx.curr_msg_id_list = NULL;
    ctx.tmp_key = NULL;
    ctx.tmp_value = NULL;
    yyparse(&ctx);

    *msg = ctx.parsed_msg;
    
    return PEP_STATUS_OK;
}


