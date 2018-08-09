// This file is under GNU General Public License 3.0
// see LICENSE.txt

// generate state machine code

// Copyleft (c) 2017, p≡p foundation

// Written by Volker Birk


#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// error values

typedef enum _fsm_error {
    // these error values are corresponding to
    // PEP_SYNC_STATEMACHINE_ERROR - value
    invalid_state = -2,
    invalid_event = -3,
    invalid_condition = -4,
    invalid_action = -5,

    // out of memory condition
    invalid_out_of_memory = -128,
} fsm_error;

// common

enum {
    End = -1,
    None = 0,
    Init = 1,
    Extra = 128 // messages will be below this ID
};

#ifdef __cplusplus
}
#endif

