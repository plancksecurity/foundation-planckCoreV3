// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif


// struct for holding group data in memory
// groups are persistant, therefore they're living in management.db

struct _pEp_group {
    pEp_identity *group_identity;
    pEp_identity *manager;
    identity_list *members;
} pEp_group;


// new_group() - allocate pEp_group struct. This function does not create a group.
//
//  params:
//      group_identity (in)
//      manager (in, optional)
//      members (in, optional)

pEp_group *new_group(pEp_identity *group_identity, pEp_identity *manager, identity_list *members);


// free_group() - free pEp_group struct. This function does not dissolve a group.

void free_group(pEp_group *group);


// group_create() - create a group

PEP_STATUS group_create(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        identity_list *members,
        pEp_group **group
    );


// group_dissolve() - dissolve a group

PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity
    );


// group_add_member() - add group member

PEP_STATUS group_add_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
    );


// group_remove_member() - remove a member from the group

PEP_STATUS group_remove_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
    );


// group_rating() - calculate the rating of the group

PEP_STATUS group_rating(
        PEP_SESSION session,
        pEp_identity *group_identity,
        PEP_rating *rating
    );


#ifdef __cplusplus
}
#endif
