#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "mailmime.h"
#include "mailmime.peg.c.src"
#include "pEpEngine.h"

PEP_STATUS parse_mailmessage(const char *mimetext,
                         message **msg) {
    PEP_STATUS status = PEP_STATUS_OK;
    message *_msg = NULL;
    
    assert(mimetext);
    assert(msg);
    
    if (!(mimetext && msg))
        return PEP_ILLEGAL_VALUE;
    
    *msg = NULL;
    
    yycontext ctx;
    memset(&ctx, 0, sizeof(yycontext));
    ctx.input_str = mimetext;
    while (yyparse(&ctx));

    return PEP_STATUS_OK;
}


