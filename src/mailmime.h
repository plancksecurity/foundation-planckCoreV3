#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAILMIME_H
#define MAILMIME_H

#include "pEpEngine.h"
#include "message.h"

#define YY_DEBUG
#define YY_CTX_LOCAL
#define YY_CTX_MEMBERS const char* input_str;    \
                       size_t index_consumed;    \
                       message* parsed_msg;     \
                       identity_list* curr_address_list; \
                       stringlist_t* curr_msg_id_list; \
                       pEp_mailmime* msg_root;      \
                       char* tmp_key;           \
                       char* tmp_value;

#define YY_INPUT(yycontext, buf, result, max_size)                        \
{                                                                         \
    const char* ref = yycontext->input_str + yycontext->index_consumed;   \
    int yyc = *(ref);                                                     \
    result= (!yyc) ? 0 : (*(buf)= yyc, 1);                                \
    yyprintf((stderr, "<%c>", yyc));			                          \
    yycontext->index_consumed += 1;                                       \
}

struct _pEpMailMime;
typedef struct _pEpMailMime pEp_mailmime;

/* These are in no way comprehensive - these are the ones we may act on. */
typedef enum {
    CONTENT_MESSAGE         =           0x100,
    CONTENT_MULTIPART       =           0x101,
    CONTENT_COMPOSITE_OTHER =           0x10F,
    
    /* IANA media types */
    CONTENT_APPLICATION     =           0x200,
    CONTENT_AUDIO           =           0x201,
    CONTENT_EXAMPLE         =           0x202,
    CONTENT_IMAGE           =           0x203,
    CONTENT_MODEL           =           0x205,
    CONTENT_TEXT            =           0x206,
    CONTENT_VIDEO           =           0x207,
    
    CONTENT_OTHER           =           0xFFF
} MIME_content_type;

/* These are in no way comprehensive - these are the ones we may act on. */
typedef enum {
    /* MULTIPART SUBTYPES */
    SUBTYPE_MIXED           =           0x100,
    SUBTYPE_DIGEST          =           0x101,
    SUBTYPE_RFC822          =           0x102,
    SUBTYPE_ALTERNATIVE     =           0x103,
    SUBTYPE_RELATED         =           0x104,
    SUBTYPE_REPORT          =           0x105,
    SUBTYPE_SIGNED          =           0x106,
    SUBTYPE_ENCRYPTED       =           0x107,
    SUBTYPE_FORMDATA        =           0x108,
    SUBTYPE_BYTERANGE       =           0x109,
    SUBTYPE_PARTIAL         =           0x10A,

    /* APPLICATION SUBTYPES WE CARE ABOUT RIGHT NOW */
    SUBTYPE_PGP_ENCRYPTED   =           0x201,
    SUBTYPE_PGP_SIGNATURE   =           0x202,
    SUBTYPE_OCTET_STREAM    =           0x203,
    
    /* TEXT SUBTYPES WE CARE ABOUT RIGHT NOW */
    SUBTYPE_PLAIN           =           0x300,
    SUBTYPE_HTML            =           0x301,
    
    SUBTYPE_OTHER           =           0xfff
} MIME_content_subtype;

typedef struct _pEpMailMime {
    char* content_id;
    MIME_content_type content_type;
    MIME_content_type content_subtype;
    pEp_mailmime* next;
    pEp_mailmime* first_child;
} pEp_mailmime;

DYNAMIC_API PEP_STATUS parse_mailmessage(const char *mimetext,
                             message **msg);

typedef struct _dual_string_index {
    char* start_0;
    unsigned int end_0;
    char* start_1;
    unsigned int end_1;
} dual_string_index;

void two_string_clear(dual_string_index* ds);

#endif

#ifdef __cplusplus
}
#endif