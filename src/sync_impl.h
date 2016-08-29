#pragma once

#include "message.h"
#include "sync_fsm.h"

#ifdef __cplusplus
extern "C" {
#endif

PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        DeviceGroup_Protocol_t *msg
    );

PEP_STATUS receive_DeviceState_msg(PEP_SESSION session, message *src);

DeviceGroup_Protocol_t *new_DeviceGroup_Protocol_msg(DeviceGroup_Protocol__payload_PR type);
void free_DeviceGroup_Protocol_msg(DeviceGroup_Protocol_t *msg);

PEP_STATUS unicast_msg(
        PEP_SESSION session,
        Identity partner,
        DeviceState_state state,
        DeviceGroup_Protocol_t *msg
    );

PEP_STATUS multicast_self_msg(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceGroup_Protocol_t *msg
    );

bool is_double(DeviceGroup_Protocol_t *msg);

#ifdef __cplusplus
}
#endif

