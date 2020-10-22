// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _pEp_group {
    pEp_identity *group_identity;
    pEp_identity *manager;
    identity_list *members;
} pEp_group;

#ifdef __cplusplus
}
#endif
