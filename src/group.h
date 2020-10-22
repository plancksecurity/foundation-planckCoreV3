// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif


// struct for holding group data in memory
// groups are persistant, therefore they're living in management.db

typedef struct _pEp_member {
    pEp_identity *ident;
    bool adopted;
} pEp_member;

typedef struct _member_list {
    pEp_member *member;
    struct _member_list *next;
} member_list;

struct _pEp_group {
    pEp_identity *group_identity;
    pEp_identity *manager;
    member_list *members;
} pEp_group;


// new_group() - allocate pEp_group struct. This function does not create a
// group.
//
//  params:
//      group_identity (in)
//      manager (in, optional)
//      memberlist (in, optional)
//
//  caveat:
//      the ownership of all parameters groes to the struct; data is not copied

pEp_group *new_group(
        pEp_identity *group_identity,
        pEp_identity *manager,
        member_list *memberlist
    );


// free_group() - free pEp_group struct. This function does not dissolve a
// group.

void free_group(pEp_group *group);


// group_create() - create group as group manager
//
//  params:
//      group_identity (in)
//      manager (in)            own identity

PEP_STATUS group_create(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        member_list *memberlist,
        pEp_group **group
    );


// group_adopt() - adopt group as member
//
//  params:
//      group_identity (in)
//      as_member (in)          own identity

PEP_STATUS group_adopt(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *as_member
    );


// group_dissolve() - dissolve a group

PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager
    );


// group_add_member() - add group member

PEP_STATUS group_add_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member,
        pEp_identity *manager
    );


// group_remove_member() - remove a member from the group

PEP_STATUS group_remove_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member,
        pEp_identity *manager
    );


// group_rating() - returns the group rating as manager or the straight rating
// otherwise

PEP_STATUS group_rating(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        PEP_rating *rating
    );


#ifdef __cplusplus
}
#endif
