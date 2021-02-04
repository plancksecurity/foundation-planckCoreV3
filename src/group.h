// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message_api.h"
#include "../asn.1/Distribution.h"

#ifdef __cplusplus
extern "C" {
#endif


// struct for holding group data in memory
// groups are persistent, therefore they're living in management.db

typedef struct _pEp_member {
    pEp_identity *ident;
    bool adopted;
} pEp_member;

pEp_member *new_member(pEp_identity *ident);
void free_member(pEp_member *member);

typedef struct _member_list {
    pEp_member *member;
    struct _member_list *next;
} member_list;

member_list *new_memberlist(pEp_member *member);
void free_memberlist(member_list *list);
member_list *memberlist_add(member_list *list, pEp_member *member);

typedef struct _pEp_group {
    pEp_identity *group_identity;
    pEp_identity *manager;
    member_list *members;
    bool active;
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


// group_create() - create group as group manager and marks it as being active
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


// join_group() - adopt group as member
//
//  params:
//      group_identity (in)
//      as_member (in)          own identity

PEP_STATUS join_group(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *as_member
    );

// leave_group() - leave group as member
//
//  params:
//      group_identity (in)
//      as_member (in)          own identity

PEP_STATUS leave_group(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *member_identity
);

// group_dissolve() - dissolve a group and marks it as being inactive

PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager
    );

PEP_STATUS group_enable(
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


// group_rating() - returns the group rating as manager or the straight rating
// otherwise

PEP_STATUS group_rating(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        PEP_rating *rating
    );

PEP_STATUS exists_group(
        PEP_SESSION session,
        pEp_identity* group_identity,
        bool* exists
);

// if status is PEP_STATUS_OK, group_identity is transferred to group.
PEP_STATUS retrieve_group_info(
        PEP_SESSION session,
        pEp_identity* group_identity,
        pEp_group** group_info
);

PEP_STATUS retrieve_full_group_membership(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** members);

PEP_STATUS retrieve_active_group_membership(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** members);

PEP_STATUS create_group_entry(PEP_SESSION session,
                              pEp_group* group);

PEP_STATUS add_own_membership_entry(PEP_SESSION session,
                                    pEp_group* group,
                                    pEp_identity* own_identity_recip);

PEP_STATUS retrieve_own_membership_info_for_group_and_identity(PEP_SESSION session,
                                                     pEp_group* group,
                                                     pEp_identity* own_identity);

PEP_STATUS receive_managed_group_message(PEP_SESSION session, message* msg, PEP_rating rating, Distribution_t* dist);

PEP_STATUS send_GroupCreate(PEP_SESSION session, pEp_group* group);
PEP_STATUS send_GroupDissolve(PEP_SESSION session, pEp_group* group);

PEP_STATUS retrieve_active_member_list(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** mbr_idents);

#ifdef __cplusplus
}
#endif
