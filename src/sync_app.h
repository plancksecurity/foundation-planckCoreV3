//
//  sync_app.h
//  pEpEngine
//
//  Created by Dirk Zimmermann on 16.05.17.
//  Copyright © 2017 Edouard Tisserant. All rights reserved.
//

#ifndef sync_app_h
#define sync_app_h

// TODO add this to generated code.
typedef enum _sync_handshake_signal {
    SYNC_NOTIFY_UNDEFINED = 0,

    // request show handshake dialog
    SYNC_NOTIFY_INIT_ADD_OUR_DEVICE,
    SYNC_NOTIFY_INIT_ADD_OTHER_DEVICE,
    SYNC_NOTIFY_INIT_FORM_GROUP,
    SYNC_NOTIFY_INIT_MOVE_OUR_DEVICE,

    // handshake process timed out
    SYNC_NOTIFY_TIMEOUT,

    // handshake accepted by user
    SYNC_NOTIFY_ACCEPTED_DEVICE_ADDED,
    SYNC_NOTIFY_ACCEPTED_GROUP_CREATED,
    SYNC_NOTIFY_ACCEPTED_DEVICE_MOVED,

    // handshake dialog must be closed
    SYNC_NOTIFY_OVERTAKEN
} sync_handshake_signal;

#endif /* sync_app_h */
