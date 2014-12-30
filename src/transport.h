#pragma once

#include "pEpEngine.h"
#include <time.h>

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


// new_identity_list() - allocate a new identity list
//
//  parameters:
//      ident               identity to move for first element
//
//  return value:
//      new identity_list or NULL if out of memory
//
//  caveat:
//      ident is being moved, the caller loses ownership

identity_list *new_identity_list(pEp_identity *ident);


// identity_list_dup() - duplicate identity_list (deep copy)
//
//  parameters:
//      id_list             identity_list to copy
//
//  return value:
//      new identity_list or NULL if out of memory

identity_list *identity_list_dup(const identity_list *src);


// free_identity_list() - free memory allocated by identity_list
//
//  parameters:
//      id_list             identity_list to free
//
//  caveat:
//      this function frees all identities in the list additional to the
//      identity_list itself

void free_identity_list(identity_list *id_list);


// identity_list_add - add identity to an identity_list
//
//  parameters:
//      id_list             identity_list to add to
//      ident               identity being added
//
//  return value:
//      pointer to the last element in identity_list or NULL if out of memory
//
//  caveat:
//      ident is being moved, the caller loses ownership

identity_list *identity_list_add(identity_list *id_list, pEp_identity *ident);

typedef enum _PEP_msg_format {
    PEP_format_plain = 0,
    PEP_format_html
} PEP_msg_format;

typedef enum _PEP_msg_direction {
    PEP_dir_incoming = 0,
    PEP_dir_outgoing
} PEP_msg_direction;

typedef struct _bloblist_t {
    char *data;                     // blob
    size_t size;                    // size of blob
    char *mime_type;                // UTF-8 string of MIME type of blob or
                                    // NULL if unknown
    char *file_name;                // UTF-8 string of file name of blob or
                                    // NULL if unknown
    struct _bloblist_t *next;
} bloblist_t;


// new_bloblist() - allocate a new bloblist
//
//  parameters:
//      blob            blob to add to the list
//      size            size of the blob
//      mime_type       MIME type of the blob data or NULL if unknown
//      file_name       file name of origin of blob data or NULL if unknown
//
//  return value:
//      pointer to new bloblist_t or NULL if out of memory
//
//  caveat:
//      the ownership of the blob goes to the bloblist; mime_type and file_name
//      are being copied, the originals remain in the ownership of the caller

bloblist_t *new_bloblist(char *blob, size_t size, const char *mime_type,
        const char *file_name);


// free_bloblist() - free bloblist
//
//  parameters:
//      bloblist        bloblist to free

void free_bloblist(bloblist_t *bloblist);


// bloblist_add() - add reference to a blob to bloblist
//
//  parameters:
//      bloblist        bloblist to add to
//      blob            blob
//      size            size of the blob
//      mime_type       MIME type of the blob or NULL if unknown
//      file_name       file name of the blob or NULL if unknown
//
//  return value:
//      pointer to the last element of bloblist or NULL if out of memory
//
//  caveat:
//      the ownership of the blob goes to the bloblist; mime_type and file_name
//      are being copied, the originals remain in the ownership of the caller

bloblist_t *bloblist_add(bloblist_t *bloblist, char *blob, size_t size,
        const char *mime_type, const char *file_name);


typedef enum _PEP_enc_format {
    PEP_enc_none = 0,
    PEP_enc_MIME_multipart,
    PEP_enc_pieces
} PEP_enc_format;

struct _message_ref_list;

typedef struct _message {
    PEP_msg_direction dir;
    char * id;                              // UTF-8 string of message ID
    char * shortmsg;                        // UTF-8 string of short message
    char * longmsg;                         // UTF-8 string of long message
                                            // (plain)
    char * longmsg_formatted;               // UTF-8 string of long message
                                            // (formatted)
    PEP_msg_format format;                  // format type
    bloblist_t * attachments;               // blobs with attachements
    char * rawmsg_ref;                      // reference to raw message data
    size_t rawmsg_size;                     // size of raw message data
    timestamp sent;                         // when the message is sent
    timestamp recv;                         // when the message is received
    pEp_identity *from;                     // whom the message is from
    identity_list *to;                      // whom the message is to
    pEp_identity *recv_by;                  // via which identity the message
                                            // is received
    identity_list *cc;                      // whom a CC is being sent
    identity_list *bcc;                     // whom a BCC is being sent
    char * refering_id;                     // UTF-8 string of refering message ID
    struct _message *refering_msg_ref;      // reference to refering message
    struct _message_ref_list *refered_by;   // list of references to messages being
                                            // refered
    PEP_enc_format enc_format;              // format of encrypted data
} message;

typedef struct _message_ref_list {
    message *msg_ref;                       // reference to message
    struct _message_ref_list *next;
} message_ref_list;


// new_message() - allocate new message
//
//  parameters:
//      dir             PEP_dir_incoming or PEP_dir_outgoing
//      from            identity whom the message is from
//      to              identity list whom the message is sent to
//      shortmsg        UTF-8 string of short message
//
//  return value:
//      pointer to new message or NULL if out of memory
//
//  caveat:
//      from and to are moved into the message, the caller loses ownership for
//      them; shortmsg is being copied, the ownership of the original remains
//      with the caller

message *new_message(
        PEP_msg_direction dir,
        pEp_identity *from,
        identity_list *to,
        const char *shortmsg
    );


// free_message() - free message struct
//
//  parameters:
//      msg             message struct to free
//
//  caveat:
//      raw data as well as referenced other messages aren't freed and remain
//      in the ownership of the caller

void free_message(message *msg);


// new_message_ref_list() - allocate new message reference list
//
//  parameters:
//      msg             message to add a reference to or NULL
//
//  return value:
//      pointer to new message_ref_list or NULL if out of memory

message_ref_list *new_message_ref_list(message *msg);


// free_message_ref_list() - free message reference list
//
//  parameters:
//      msg_list        message_ref_list to free

void free_message_ref_list(message_ref_list *msg_list);


// message_ref_list_add() - add a reference to a message to a message reference
// list
//
//  parameters:
//      msg_list        message_ref_list to add to
//      msg             message to add a reference to
//
//  return value:
//      pointer to the last element of message_ref_list or NULL if out of
//      memory

message_ref_list *message_ref_list_add(message_ref_list *msg_list,
        message *msg);


typedef PEP_STATUS (*sendto_t)(PEP_SESSION session, const message *msg);
typedef PEP_STATUS (*readnext_t)(PEP_SESSION session, message **msg,
        PEP_transport_t **via);

struct _PEP_transport_t {
    uint8_t id;                             // transport ID
    sendto_t sendto;                        // sendto function
    readnext_t readnext;                    // readnext function
    bool long_message_supported;            // flag if this transport supports
                                            // long messages
    bool formatted_message_supported;       // flag if this transport supports
                                            // formatted messages
    PEP_msg_format native_format;           // native format of the transport
};

typedef uint64_t transports_mask;

PEP_STATUS init_transport_system(PEP_SESSION session);
void release_transport_system(PEP_SESSION session);

