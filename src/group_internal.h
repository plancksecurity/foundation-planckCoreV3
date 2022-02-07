/// @file group_internal.h
/// @brief  Internal functions for representation of groups
/// @license This file is under GNU General Public License 3.0 - see LICENSE.txt

#ifndef GROUP_INTERNAL_H
#define GROUP_INTERNAL_H


#include "message_api.h"
#include "../asn.1/Distribution.h"
#include "group.h"

#ifdef __cplusplus
extern "C" {
#endif


/*************************************************************************************************
 * Internal functions
 *************************************************************************************************/

/**
 * @internal
 *
 *  <!--       group_enable()       -->
 *
 *  @brief          Mark an extant group in the database as active
 *
 *  @param[in]      session             associated session object
 *  @param[in]      group_identity      the pEp_identity object representing the group. Must contain at least
 *                                      a user_id and address
 *
 *  @retval         PEP_STATUS_OK       on success
 *  @retval         error               on failure
 *
 *  @ownership      all arguments belong to the callee
 *
 */
PEP_STATUS group_enable(
        PEP_SESSION session,
        pEp_identity *group_identity
);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param group_member
 * @return
 */
PEP_STATUS group_add_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
    );

// leave_group() - leave group as member
//
//  params:
//      group_identity (in)
//      as_member (in)          own identity
/**
 * @internal
 *
 * @param[in] session
 * @param[in] group_identity
 * @param[in] member_identity
 * @return
 */
PEP_STATUS leave_group(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *member_identity
);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param exists
 * @return
 */
PEP_STATUS exists_group(
        PEP_SESSION session,
        pEp_identity* group_identity,
        bool* exists
);

// group_identity stays with caller now - FIXME: adapt assumptions
/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param group_info
 * @return
 */
PEP_STATUS retrieve_group_info(
        PEP_SESSION session,
        pEp_identity* group_identity,
        pEp_group** group_info
);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param active
 * @return
 */
PEP_STATUS is_group_active(
        PEP_SESSION session,
        pEp_identity*
        group_identity,
        bool* active);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param members
 * @return
 */
PEP_STATUS retrieve_full_group_membership(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** members);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param members
 * @return
 */
PEP_STATUS retrieve_active_group_membership(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** members);

/**
 * @internal
 *
 * @param session
 * @param group
 * @return
 */
PEP_STATUS create_group_entry(PEP_SESSION session,
                              pEp_group* group);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param manager
 * @param own_identity_recip
 * @return
 */
PEP_STATUS add_own_membership_entry(PEP_SESSION session,
                                    pEp_identity* group_identity,
                                    pEp_identity* manager,
                                    pEp_identity* own_identity_recip);

/**
 * @internal
 *
 * @param session
 * @param group
 * @param own_identity
 * @return
 */
PEP_STATUS retrieve_own_membership_info_for_group_and_identity(PEP_SESSION session,
                                                     pEp_group* group,
                                                     pEp_identity* own_identity);

/**
 * @internal
 *
 * @param session
 * @param msg
 * @param rating
 * @param dist
 * @return
 */
PEP_STATUS receive_managed_group_message(PEP_SESSION session, message* msg, PEP_rating rating, Distribution_t* dist);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param mbr_idents
 * @return
 */
PEP_STATUS retrieve_active_member_list(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** mbr_idents);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param as_member
 * @param active
 * @return
 */
PEP_STATUS set_membership_status(PEP_SESSION session,
                                 pEp_identity* group_identity,
                                 pEp_identity* as_member,
                                 bool active);

/**
 * @internal
 *
 * @param session
 * @param group_identity
 * @param is_own
 * @return
 */
PEP_STATUS is_own_group_identity(PEP_SESSION session, pEp_identity* group_identity, bool* is_own);

/**
 * @internal
 *
 * @param memberlist
 * @return
 */
identity_list* member_list_to_identity_list(member_list* memberlist);

/**
 *
 * @param session
 * @param group_identity
 * @param manager
 * @return
 */
PEP_STATUS get_group_manager(PEP_SESSION session,
                             pEp_identity* group_identity,
                             pEp_identity** manager);

/**
 *
 * @param session
 * @param group_identity
 * @param own_manager
 * @return
 */
PEP_STATUS is_group_mine(PEP_SESSION session, pEp_identity* group_identity, bool* own_manager);

/**
 *
 * @param session
 * @param group_identity
 * @param member
 * @param is_active
 * @return
 */
PEP_STATUS is_active_group_member(PEP_SESSION session, pEp_identity* group_identity,
                                  pEp_identity* member, bool* is_active);
#ifdef __cplusplus
}
#endif

#endif
