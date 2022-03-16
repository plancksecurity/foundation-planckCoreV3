/**
 * @file     src/fsm_common.h
 * @brief    Generate state machine code
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 * @copyleft (c) 2017-2018, pEp foundation 
 * @author   Volker Birk
 */


#ifndef FSM_COMMON_H
#define FSM_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

// error values

/**
 *  @enum    fsm_error
 *  
 *  @brief   TODO
 *
 *   error values -2..-7 are corresponding to
 *   PEP_SYNC_STATEMACHINE_ERROR - value
 *  
 */
typedef enum _fsm_error {
    // these error values are corresponding to
    // PEP_SYNC_STATEMACHINE_ERROR - value
    invalid_state = -2,
    invalid_event = -3,
    invalid_condition = -4,
    invalid_action = -5,
    inhibited_event = -6,
    cannot_send = -7,

    // out of memory condition
    out_of_memory = -128,
} fsm_error;

// common

enum {
    End = -1,
    None = 0,
    Init = 1,
    Extra = 128 // messages will be below this ID
};

enum {
    SHUTDOWN = 0
};

#ifdef __cplusplus
}
#endif

#endif
