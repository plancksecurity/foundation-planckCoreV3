#pragma once

#include "pEpEngine.h"
#include <time.h>
#include <stdlib.h>

// all functions are using POSIX struct tm

typedef struct tm timestamp;

typedef enum _PEP_transports {
    // auto transport chooses transport per message automatically
    PEP_trans_auto = 0,
//    PEP_trans_email,
//    PEP_trans_whatsapp,

    PEP_trans__count
} PEP_transports;

typedef struct _PEP_transport_t PEP_transport_t;

typedef struct _identity_list {
    pEp_identity *ident;
    struct _identity_list *next;
} identity_list;

identity_list *new_identity_list(const pEp_identity *ident);
identity_list *identity_list_dup(const identity_list *src);
void free_identity_list(identity_list *id_list);
identity_list *identity_list_add(identity_list *id_list, const pEp_identity *ident);

typedef enum _PEP_msg_format {
    PEP_format_plain = 0,
    PEP_format_html
} PEP_msg_format;

typedef enum _PEP_msg_direction {
    PEP_dir_incoming = 0,
    PEP_dir_outgoing
} PEP_msg_direction;

typedef struct _bloblist_t {
    char *data_ref;
    size_t size;
    struct _bloblist_t *next;
} bloblist_t;

bloblist_t *new_bloblist(char *blob, size_t size);
bloblist_t *bloblist_dup(const bloblist_t *src);
void free_bloblist(bloblist_t *bloblist);
bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size);

struct _message_ref_list;

typedef struct _message {
    PEP_msg_direction dir;
    char * id;
    size_t id_size;
    char * shortmsg;
    size_t shortmsg_size;
    char * longmsg;
    size_t longmsg_size;
    char * longmsg_formatted;
    size_t longmsg_formatted_size;
    PEP_msg_format format;
    bloblist_t * attachments;
    char * rawmsg;
    size_t rawmsg_size;
    timestamp sent;
    timestamp recv;
    pEp_identity *from;
    identity_list *to;
    pEp_identity *recv_by;
    identity_list *cc;
    identity_list *bcc;
    char * refering_id;
    size_t refering_id_size;
    struct _message *refering_msg;
    struct _message_ref_list *refered_by;
    bool encrypted;
} message;

typedef struct _message_ref_list {
    message *msg_ref;
    struct _message_ref_list *next;
} message_ref_list;

message *new_message(
        PEP_msg_direction dir,
        const pEp_identity *from,
        const identity_list *to,
        const char *shortmsg
    );

void free_message(message *msg);

message_ref_list *new_message_ref_list(message *msg);
void free_message_ref_list(message_ref_list *msg_list);
message_ref_list *message_ref_list_add(message_ref_list *msg_list, message *msg);

typedef PEP_STATUS (*sendto_t)(PEP_SESSION session, const message *msg);
typedef PEP_STATUS (*readnext_t)(PEP_SESSION session, message **msg, PEP_transport_t **via);

struct _PEP_transport_t {
    uint8_t id;
    sendto_t sendto;
    readnext_t readnext;
    bool long_message_supported;
    PEP_msg_format native_format;
};

typedef uint64_t transports_mask;

PEP_STATUS init_transport_system(PEP_SESSION session);
void release_transport_system(PEP_SESSION session);

