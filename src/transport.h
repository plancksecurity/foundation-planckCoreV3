#pragma once

#include <time.h>
#include "pEpEngine.h"
#include "identity_list.h"
#include "bloblist.h"
#include "stringpair.h"

#ifdef __cplusplus
extern "C" {
#endif

// for time values all functions are using POSIX struct tm

typedef struct tm timestamp;

typedef enum _PEP_transports {
    // auto transport chooses transport per message automatically
    PEP_trans_auto = 0,
//    PEP_trans_email,
//    PEP_trans_whatsapp,

    PEP_trans__count
} PEP_transports;

typedef struct _PEP_transport_t PEP_transport_t;

typedef enum _PEP_text_format {
    PEP_text_format_plain = 0,
    PEP_text_format_html,
    PEP_text_format_other = 0xff
} PEP_text_format;

typedef enum _PEP_msg_direction {
    PEP_dir_incoming = 0,
    PEP_dir_outgoing
} PEP_msg_direction;

typedef enum _PEP_enc_format {
    PEP_enc_none = 0,                       // message is in pieces and nor
                                            // encoded nor encrypted
    PEP_enc_none_MIME,                      // message is MIME encoded but not
                                            // encrypted
    PEP_enc_pieces,                         // message is encrypted but not
                                            // MIME encoded
    PEP_enc_MIME_multipart,                 // message is encrypted and MIME
                                            // encoded; this is being used for
                                            // PGP/MIME as well as S/MIME
    PEP_enc_PEP                             // pEp encryption format
} PEP_enc_format;

struct _message_ref_list;

typedef struct _message {
    PEP_msg_direction dir;
    char *id;                               // UTF-8 string of message ID
    char *shortmsg;                         // UTF-8 string of short message
    char *longmsg;                          // UTF-8 string of long message
                                            // (plain)
    char *longmsg_formatted;                // UTF-8 string of long message
                                            // (formatted)
    bloblist_t *attachments;                // blobs with attachements
    char *rawmsg_ref;                       // reference to raw message data
    size_t rawmsg_size;                     // size of raw message data
    timestamp *sent;                        // when the message is sent
    timestamp *recv;                        // when the message is received
    pEp_identity *from;                     // whom the message is from
    identity_list *to;                      // whom the message is to
    pEp_identity *recv_by;                  // via which identity the message
                                            // is received
    identity_list *cc;                      // whom a CC is being sent
    identity_list *bcc;                     // whom a BCC is being sent
    identity_list *reply_to;                // where a reply should go to
    stringlist_t *in_reply_to;              // list of UTF-8 strings with
                                            // MessageIDs ofrefering messages
    struct _message *refering_msg_ref;      // reference to refering message
    stringlist_t *references;               // list of UTF-8 strings with references
    struct _message_ref_list *refered_by;   // list of references to messages being
                                            // refered
    stringlist_t *keywords;                 // list of UTF-8 strings with keywords
    char *comments;                         // UTF-8 string with comments
    stringpair_list_t *opt_fields;          // optional fields
    PEP_enc_format enc_format;              // format of encrypted data
} message;

typedef struct _message_ref_list {
    message *msg_ref;                       // reference to message
    struct _message_ref_list *next;
} message_ref_list;


// new_message() - allocate new message
//
//  parameters:
//      dir (in)        PEP_dir_incoming or PEP_dir_outgoing
//      from (in)       identity whom the message is from
//      to (in)         identity list whom the message is sent to
//      shortmsg (in)   UTF-8 string of short message
//
//  return value:
//      pointer to new message or NULL if out of memory
//
//  caveat:
//      from and to are moved into the message, the caller loses ownership for
//      them; shortmsg is being copied, the ownership of the original remains
//      with the caller

DYNAMIC_API message *new_message(
        PEP_msg_direction dir,
        pEp_identity *from,
        identity_list *to,
        const char *shortmsg
    );


// free_message() - free message struct
//
//  parameters:
//      src (in)        message struct to free
//
//  caveat:
//      raw data as well as referenced other messages aren't freed and remain
//      in the ownership of the caller

DYNAMIC_API void free_message(message *src);


// message_dup - duplicate message (deep copy)
//
//  parameters:
//      msg (in)        message to duplicate
//
//  return value:
//      pointer to duplicate of message pointed by msg or NULL

DYNAMIC_API message * message_dup(const message *msg);

// new_message_ref_list() - allocate new message reference list
//
//  parameters:
//      msg (in)        message to add a reference to or NULL
//
//  return value:
//      pointer to new message_ref_list or NULL if out of memory

DYNAMIC_API message_ref_list *new_message_ref_list(message *msg);


// free_message_ref_list() - free message reference list
//
//  parameters:
//      msg_list (in)   message_ref_list to free

DYNAMIC_API void free_message_ref_list(message_ref_list *msg_list);


// message_ref_list_dup() - duplicate message reference list
//
//  paramters:
//      src (in)        message_ref_list to duplicate
//
//  return value:
//      pointer to new message_ref_list or NULL if out of memory

DYNAMIC_API message_ref_list *message_ref_list_dup(
        const message_ref_list *src
    );

// message_ref_list_add() - add a reference to a message to a message reference
// list
//
//  parameters:
//      msg_list (in)   message_ref_list to add to
//      msg (in)        message to add a reference to
//
//  return value:
//      pointer to the last element of message_ref_list or NULL if out of
//      memory

DYNAMIC_API message_ref_list *message_ref_list_add(message_ref_list *msg_list,
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
    PEP_text_format native_text_format;     // native format of the transport
};

typedef uint64_t transports_mask;

#ifdef __cplusplus
}
#endif

