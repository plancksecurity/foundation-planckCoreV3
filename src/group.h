#ifndef GROUP_H
#define GROUP_H

/**
 * @file group.h
 * @brief In-memory objects and functions for representation of groups
 *
 * @license This file is under GNU General Public License 3.0 - see LICENSE.txt
 *
 */

 // 23.08.2023/IG - Update group_rating doc: Group rating is now Reliable (not Trusted) for members.

#include "platform.h"
#include "dynamic_api.h"
#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/***
 * TODO: Note in EACH call that update_identity/myself must be called before entry into the functions
 */

/*************************************************************************************************
 * In-memory objects and functions for representation of groups
 *************************************************************************************************/

/**
 * <!-- pEp_member -->
 * @brief  memory object for holding information about an invited group member
 *         and whether they have joined the group
 *         (groups are persistent and are stored in the management database)
 */
typedef struct _pEp_member {
    pEp_identity *ident;      //!< member identity
    bool joined;              //!< boolean for whether the member has accepted the invite
} pEp_member;

/**
 *  <!--       new_member()       -->
 *
 *  @brief      allocate pEp_member struct. This struct only allocates the member object for
 *              group representation.
 *
 *  @param[in]      ident               the pEp_identity object representing the member
 *
 *  @retval         pEp_member          allocated member struct on success
 *  @retval         NULL                if ident is not present or other failure occurs
 *
 *  @ownership      ownership of all parameters goes to the struct
 *
 *  @warning        This is only an in-memory object allocator and performs NONE of the
 *                  database or key management functions for groups or members!
 *
 */
DYNAMIC_API pEp_member *new_member(pEp_identity *ident);

/**
 *  <!--       free_member()       -->
 *
 *  @brief      deallocate pEp_member struct and the identity it points to.
 *
 *  @param[in]      member      member object to be freed
 *
 *  @ownership      ALL objects pointed to by the struct will be freed!
 *
 *  @warning        This is only an in-memory object deallocator and performs NONE of the
 *                  database or key management functions for group members!
 *
 */
DYNAMIC_API void free_member(pEp_member *member);

//  @typedef member_list
/**
 * @brief  list structure for pEp_member objects
 * @see    pEp_member
 */
typedef struct _member_list {
    pEp_member *member;             //!< member object containing the identity and joined status for this list node
    struct _member_list *next;      //!< pointer to next node in list
} member_list;


/**
 *  <!--       new_memberlist()       -->
 *
 *  @brief      allocate member_list node struct. This struct only allocates the member_list object for
 *              group representation.
 *
 *  @param[in]      member              the member to be associated with this member_list node
 *
 *  @retval         member_list         allocated member_list struct on success
 *                  NULL                if failure occurs (typically: out of memory)
 *
 *  @ownership      ownership of all parameters goes to the struct
 *
 *  @warning        This is only an in-memory object allocator and performs NONE of the
 *                  database or key management functions for groups or members!
 *
 */
DYNAMIC_API member_list *new_memberlist(pEp_member *member);

/**
 *  <!--       free_memberlist()       -->
 *
 *  @brief          deallocate the node pointed to by the list argument and all nodes following it in the list
 *                  and their associated objects
 *
 *  @param[in]      list      memberlist object to be freed
 *
 *  @ownership      ALL objects pointed to by the struct will be freed!
 *
 *  @warning        This is only an in-memory object deallocator and performs NONE of the
 *                  database or key management functions for group members!
 *
 */
DYNAMIC_API void free_memberlist(member_list *list);

/**
 *  <!--       memberlist_add()       -->
 *
 *  @brief      add memberlist node containing this member to the end of the list
 *              pointed to by the list argument and return a pointer to the tail of the list
 *
 *  @param[in,out]  list                node pointing to the list to add to (if this is NULL,
 *                                      a new list will be created and returned)
 *  @param[in]      member              member to add to the list
 *
 *  @retval         member_list         tail of list on success (or pointer to new list if input list was NULL)
 *  @retval         NULL                if failure occurs (typically: out of memory)
 *
 *  @ownership      ownership of all parameters goes to the callee
 *
 *  @warning        This is only an in-memory object allocator and performs NONE of the
 *                  database or key management functions for groups or members!
 *
 */
DYNAMIC_API member_list *memberlist_add(member_list *list, pEp_member *member);

/**
 * <!-- pEp_group -->
 *
 * @brief  memory object for holding all information about a group
 *         (groups are persistent and are stored in the management database)
 */
typedef struct _pEp_group {
    pEp_identity *group_identity;   //!< identity representing this group
    pEp_identity *manager;          //!< identity of the group manager
    member_list *members;           //!< list of members associated with group
    bool active;                    //!< boolean true if group is marked as active, else false
} pEp_group;

/**
 *  <!--       new_group()       -->
 *
 *  @brief      allocate pEp_group struct. 
 *
 *  @warning This function does not create
 *  a group in the database, it only allocates the object for
 *  group representation.
 *
 *  @param[in]      group_identity      the pEp_identity object representing the group
 *  @param[in]      manager             the pEp_identity object representing the group's manager
 *  @param[in]      memberlist          optional list of group members
 *
 *  @retval         group               allocated group struct on success
 *                  NULL                if group_identity is not present or other failure occurs
 *
 *  @ownership      ownership of all parameters goes to the struct
 *
 *  @warning        This is only an in-memory object allocator and performs NONE of the
 *                  database or key management functions for groups!
 *
 */
DYNAMIC_API pEp_group *new_group(
        pEp_identity *group_identity,
        pEp_identity *manager,
        member_list *memberlist
    );

/**
 *  <!--       free_group()       -->
 *
 *  @brief      deallocate pEp_group struct and all objects it points to.
 *
 *  @warning    This function does not dissolve groups, only deallocates the memory object
 *              representing a group.
 *
 *  @param[in]      group      group object to be freed
 *
 *  @ownership      ALL objects pointed to by the struct will be freed!
 *
 *  @warning        This is only an in-memory object deallocator and performs NONE of the
 *                  database or key management functions for groups!
 *
 */
DYNAMIC_API void free_group(pEp_group *group);

/*************************************************************************************************
 * Group management functions
 *************************************************************************************************/

/**
 *  <!--       group_create()       -->
 *
 *  @brief      Create a group in the database with the input group_identity and manager and invite new members to the group
 *              if this is an own group (for the external API, this is always the case).
 *
 *              This function sets up the actual database structures for a group and invites new members to the group.
 *
 *              For the external API, it is used when creating an own group. The group is represented by the
 *              incoming group_identity, which contains the user_id and address for the group.
 *              If no key is present for the former, it will be generated - if there is already
 *              a default key for the group_identity in the database, that will be used instead.
 *              The manager
 *
 *  @param[in]      session             associated session object
 *  @param[in,out]  group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *  @param[in,out]  manager             the pEp_identity object representing the group's manager. Must contain
 *                                      a user_id and address, and there must be a default key for the manager
 *                                      present in the database
 *  @param[in,out]  member_ident_list   list of group member identities
 *  @param[in,out]  group               Optional reference for pointer to group object
 *                                      representing the created group.
 *                                      (When input is NULL, no object is created)
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      All input values stay with the caller
 *
 *  @warning        starts a DB transaction - do not call from within a function which
 *                  is already in the middle of another one.
 *
 *  @note           in,out fields are labelled as such because they get updated by update_identity()/myself()
 *                  and have group flags added. group_identity may have its user_id freed and replaced
 *                  with the canonical own user id.
 *
 */
DYNAMIC_API PEP_STATUS group_create(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        identity_list *member_ident_list,
        pEp_group **group
    );

/**
 *  <!--       group_join()       -->
 *
 *  @brief          Join a group for which we have received an invitation, marking
 *                  our own membership in the database for the group and sending the manager
 *                  a confirmation of the acceptance of the invitation
 *
 *  @param[in]      session             associated session object
 *  @param[in]      group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *  @param[in]      as_member           the pEp_identity object representing the own identity we want to use to
 *                                      join the group. This must match the identity which was invited to the group.
 *                                      Must contain a user_id and address.
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      FIXME
 *
 *
 */
DYNAMIC_API PEP_STATUS group_join(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *as_member
    );

/**
 *  <!--       group_dissolve()       -->
 *
 *  @brief          Dissolve a group, revoke its key, notify all members of the dissolution and
 *                  revocation, and mark the group as inactive in the database
 *
 *  @param[in]      session             associated session object
 *  @param[in]      group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *  @param[in]      manager             the pEp_identity object representing the group's manager. Must contain
 *                                      a user_id and address, and there must be a default key for the manager
 *                                      present in the database
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      FIXME
 *
 *  @warning        For recipients to accept the dissolution, the sender/manager key used must be a key that they
 *                  have a trust entry for.
 */
DYNAMIC_API PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager
    );

/**
 *  <!--       group_invite_member()       -->
 *
 *  @brief      Invite a member to an extant group, marking the member as invited in the database and
 *              sending out an invitation to said member
 *
 *  @param[in]      session             associated session object
 *  @param[in]      group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *  @param[in]      group_member        the pEp_identity object representing the member to invite. Must contain
 *                                      a user_id and address, and there must be a default key for the member
 *                                      present in the database
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      FIXME
 *
 *  @note           This generates a GroupInvite message even though the group already exists - this is because
 *                  this is the accepted message format for invitations to potential members
 *
 */
DYNAMIC_API PEP_STATUS group_invite_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
    );

/**
 *  <!--       group_remove_member()       -->
 *
 *  @brief      Remove a member from a group, deleting the member from the member list and executing a key
 *              reset on the group identity
 *
 *  @param[in]      session             associated session object
 *  @param[in]      group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *  @param[in]      group_member        the pEp_identity object representing the member to remove. Must contain
 *                                      a user_id and address
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      FIXME
 *
 *  @todo           Revamp implementation and execute key reset
 *
 */
DYNAMIC_API PEP_STATUS group_remove_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
    );

/**
 *  <!--       group_rating()       -->
 *
 *  @brief      Get the rating for this group - if the caller is the manager, this will return the aggregate rating
 *              of group members. For members, this will return PEP_rating_reliable as default since the rating of
 *              the whole group cannot be calculated.
 *
 *  @param[in]      session             associated session object
 *  @param[in]      group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *  @param[in]      manager             the pEp_identity object representing the member to remove. Must contain
 *                                      a user_id and address
 *  @param[out]     rating              the group rating
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      FIXME
 *
 */
DYNAMIC_API PEP_STATUS group_rating(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        PEP_rating *rating
    );

#ifdef __cplusplus
}
#endif

#endif
