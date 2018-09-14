// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "key_reset.h"

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "message_api.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

// FIXME: Proper docs!
//  Algorithm:
// 
//     Key Reset trigger; either manually or in another protocol, parameter key (optional)
// 
//     if identity given:
// 
//     key reset for one identity
// 
//     else
// 
//     For identity in own identities
// 
//     key reset for one identitiy
// 
//     Key Reset for identity:
// 
//     if own identity:
// 
//     Create revocation
// 
//     add to revocation list
// 
//     mistrust fpr from trust
// 
//     Remove fpr from ALL identities
// 
//     Remove fpr from ALL users
// 
//     generate new key
// 
//     for all active communication partners:
// 
//     active_send revocation
// 
//     else
// 
//     remove fpr from all identities
// 
//     remove fpr from all users
// 
//     delete key from key ring
DYNAMIC_API PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident
    );

PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted);

PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* revoke_fpr,
        const char* contact_id
    );

PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg);

PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr);
                                               
PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     const char* old_fpr, 
                                     const char* new_fpr);
    
#ifdef __cplusplus
}
#endif
