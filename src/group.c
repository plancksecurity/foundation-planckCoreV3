// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "group.h"
#include "pEp_internal.h"
#include "message_api.h"

pEp_member *new_member(pEp_identity *ident) {
    if (!ident)
        return NULL;
    pEp_member* member = (pEp_member*)calloc(1, sizeof(pEp_member));
    member->ident = ident;
    return member;
}

void free_member(pEp_member *member) {
    if (member) {
        free_identity(member->ident);
        free(member);
    }
}

member_list *new_memberlist(pEp_member *member) {
    member_list* retval = (member_list*)(calloc(1, sizeof(member_list)));
    if (!retval)
        return NULL;
    retval->member = member;
    return retval;
}

void free_memberlist(member_list *list) {
    member_list* curr = list;

    while (curr) {
        member_list *next = curr->next;
        free_member(curr->member);
        free(curr);
        curr = next;
    }
}

member_list *memberlist_add(member_list *list, pEp_member *member) {
    if (!list)
        return new_memberlist(member);

    if (!list->member) {
        list->member = member;
        return list;
    }

    member_list* curr = list;
    member_list** last_ptr = NULL;
    while (curr) {
        last_ptr = &(curr->next);
        curr = curr->next;
    }

    *last_ptr = new_memberlist(member);
    return *last_ptr;

}

pEp_group *new_group(
        pEp_identity *group_identity,
        pEp_identity *manager,
        member_list *memberlist
) {
    if (!group_identity)
        return NULL;

    pEp_group* retval = (pEp_group*)calloc(1, sizeof(pEp_group));
    if (!retval)
        return NULL;

    retval->group_identity = group_identity;
    retval->manager = manager;
    retval->members = memberlist;

    return retval;
}

void free_group(pEp_group *group) {
    free_identity(group->group_identity);
    free_identity(group->manager);
    free_memberlist(group->members);
}

// group_identity MUST have been myself'd.
// Called only from create_group and PRESUMES group, group->identity (user_id and address),
// group->manager (user_id and address) are there AND VALIDATED. This is JUST the DB call factored out.
static PEP_STATUS create_group_entry(PEP_SESSION session,
                                     pEp_group* group) {
    pEp_identity* group_identity = group->group_identity;
    pEp_identity* manager = group->manager;

    int result = 0;

    sqlite3_bind_text(session->create_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->create_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->create_group, 3, manager->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->create_group, 4, manager->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->create_group);

    sqlite3_reset(session->create_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

PEP_STATUS group_create(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        member_list *memberlist,
        pEp_group **group
) {
    if (!session || !group_identity || !manager)
        return PEP_ILLEGAL_VALUE;

    if (!group_identity->address || !manager->address)
        return PEP_ILLEGAL_VALUE;

    if (!is_me(session, manager))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    if (!group_identity->user_id || !is_me(session, group_identity)) {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        if (status != PEP_STATUS_OK)
            return status;

        free(group_identity->user_id);
        group_identity->user_id = own_id;
    }

    // We have an address, create a key for the group
    status = myself(session, group_identity);
    if (status != PEP_STATUS_OK)
        return status;

    // Do we already have this group?
    bool already_exists = false;
    status = exists_group(session, group_identity, &already_exists);
    if (already_exists)
        return PEP_GROUP_EXISTS;

    // set it as a group_identity
    status = set_identity_flags(session, group_identity, group_identity->flags | PEP_idf_group_ident);
    if (status != PEP_STATUS_OK)
        return status;

    // update the manager ident
    status = myself(session, manager);
    if (status != PEP_STATUS_OK)
        return status;

    if (manager->flags & PEP_idf_group_ident)
        return PEP_ILLEGAL_VALUE;

    // Ok, we're ready to do DB stuff. Do some allocation:
    pEp_group* _group = new_group(group_identity, manager, memberlist);
    if (!_group)
        return PEP_OUT_OF_MEMORY;

    sqlite3_exec(session->db, "BEGIN TRANSACTION ;", NULL, NULL, NULL);

    status = create_group_entry(session, _group);

    if (status == PEP_STATUS_OK) {
        member_list* curr_member = NULL;
        // Will bail if adding fails.
        for (curr_member = memberlist; curr_member && curr_member->member && status == PEP_STATUS_OK;
             curr_member = curr_member->next) {
            if (!curr_member->member->ident)
                status = PEP_ILLEGAL_VALUE;
            else {
                pEp_identity *member = curr_member->member->ident;
                if (EMPTYSTR(member->user_id) || EMPTYSTR(member->address)) {
                    status = PEP_ILLEGAL_VALUE;
                } else {
                    status = group_add_member(session, group_identity, member);
                }
            }
        }
    }

    if (status == PEP_STATUS_OK) {
        status = group_enable(session, group_identity);
    }

    if (status != PEP_STATUS_OK) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        goto pEp_free;
    }
    sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);

    *group = _group;

    return PEP_STATUS_OK;

pEp_free:
    free_group(_group);
    *group = NULL;
    return status;
}

// This presumes these values have been checked!!!!!!!!
PEP_STATUS add_own_membership_entry(PEP_SESSION session,
                            pEp_identity* group_identity,
                            pEp_identity* own_identity_recip) {
    if (!session || !group_identity || !own_identity_recip)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) || EMPTYSTR(group_identity->address))
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(own_identity_recip->user_id) || EMPTYSTR(own_identity_recip->address))
        return PEP_ILLEGAL_VALUE;

    int result = 0;

    sqlite3_bind_text(session->add_own_membership_entry, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 3, own_identity_recip->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 4, own_identity_recip->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->add_own_membership_entry);

    sqlite3_reset(session->add_own_membership_entry);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

PEP_STATUS get_own_membership_status(PEP_SESSION session,
                                     pEp_identity* group_identity,
                                     pEp_identity* own_identity,
                                     bool* have_joined) {
    PEP_STATUS status = PEP_STATUS_OK;

    sqlite3_reset(session->get_own_membership_status);
    sqlite3_bind_text(session->get_own_membership_status, 1, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 2, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 3, own_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 4, own_identity->address, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->get_own_membership_status);

    switch (result) {
        case SQLITE_ROW: {
            *have_joined = sqlite3_column_int(session->get_own_membership_status, 0);
            break;
        }
        default:
            status = PEP_NO_MEMBERSHIP_STATUS_FOUND;
    }

    sqlite3_reset(session->get_own_membership_status);

    return status;
}

PEP_STATUS join_group(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *as_member
) {

    if (!session || !group_identity || !as_member)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) || EMPTYSTR(as_member->user_id) ||
        EMPTYSTR(group_identity->address) || EMPTYSTR(as_member->address)) {
        return PEP_ILLEGAL_VALUE;
    }

    // get our status, if there is any
    bool am_member = false;
    // FIXME: differentiate between no records and DB error in call
    PEP_STATUS status = get_own_membership_status(session, group_identity, as_member, &am_member);

    if (status != PEP_STATUS_OK)
        return status;

    if (am_member)
        return PEP_STATUS_OK; // FIXME: ask Volker if there is a reason to do this, like the message wasn't sent

    // Ok, group invite exists. Do it.
    
    int result = 0;

    sqlite3_reset(session->join_group);

    sqlite3_bind_text(session->join_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->join_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->join_group, 3, as_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->join_group, 4, as_member->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->join_group);

    sqlite3_reset(session->join_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

PEP_STATUS leave_group(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *member_identity
) {
    if (!session || !group_identity || !member_identity)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) || EMPTYSTR(member_identity->user_id) ||
        EMPTYSTR(group_identity->address) || EMPTYSTR(member_identity->address)) {
        return PEP_ILLEGAL_VALUE;
    }

    // get our status, if there is any
    bool am_member = false;
    // FIXME: differentiate between no records and DB error in call
    PEP_STATUS status = get_own_membership_status(session, group_identity, member_identity, &am_member);

    if (status != PEP_STATUS_OK)
        return status;

    if (!am_member)
        return PEP_STATUS_OK; // FIXME: ask Volker if there is a reason to do this, like the message wasn't sent

    // Ok, group invite exists. Do it.

    int result = 0;

    sqlite3_reset(session->leave_group);

    sqlite3_bind_text(session->leave_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 3, member_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 4, member_identity->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->leave_group);

    sqlite3_reset(session->leave_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

PEP_STATUS group_enable(
        PEP_SESSION session,
        pEp_identity *group_identity
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    int result = 0;

    sqlite3_reset(session->enable_group);

    sqlite3_bind_text(session->enable_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->enable_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->enable_group);

    sqlite3_reset(session->enable_group);

    if (result != SQLITE_DONE)
        status = PEP_CANNOT_ENABLE_GROUP;

    return status;
}

PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    int result = 0;

    sqlite3_reset(session->disable_group);

    sqlite3_bind_text(session->disable_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->disable_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->disable_group);

    sqlite3_reset(session->disable_group);

    if (result != SQLITE_DONE)
        status = PEP_CANNOT_ENABLE_GROUP;

    return status;
}

// N.B. Call update_identity first!!
PEP_STATUS group_add_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    int result = 0;

    sqlite3_reset(session->group_add_member);

    sqlite3_bind_text(session->group_add_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_add_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_add_member, 3, group_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_add_member, 4, group_member->address, -1,
                      SQLITE_STATIC);


    result = sqlite3_step(session->group_add_member);

    sqlite3_reset(session->group_add_member);

    if (result != SQLITE_DONE)
        status = PEP_CANNOT_ADD_GROUP_MEMBER;

    return status;
}

PEP_STATUS group_remove_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    int result = 0;

    sqlite3_reset(session->group_deactivate_member);

    sqlite3_bind_text(session->group_deactivate_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_deactivate_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_deactivate_member, 3, group_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_deactivate_member, 4, group_member->address, -1,
                      SQLITE_STATIC);

    result = sqlite3_step(session->group_deactivate_member);

    sqlite3_reset(session->group_deactivate_member);

    if (result != SQLITE_DONE)
        status = PEP_CANNOT_DEACTIVATE_GROUP_MEMBER;

    return status;
}

PEP_STATUS retrieve_full_group_membership(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** members)
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (!session || !group_identity || !members)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) || EMPTYSTR(group_identity->address))
        return PEP_ILLEGAL_VALUE;

    *members = NULL;

    sqlite3_reset(session->get_all_members);
    sqlite3_bind_text(session->get_all_members, 1, group_identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_all_members, 2, group_identity->address, -1, SQLITE_STATIC);
    int result;

    member_list* retval = NULL;
    member_list** member_list_next = &retval;

    while ((result = sqlite3_step(session->get_all_members)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity((const char *) sqlite3_column_text(session->get_all_members, 1),
                                           NULL,(const char *) sqlite3_column_text(session->get_all_members, 0),
                                           NULL);
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_all_members);
            return PEP_OUT_OF_MEMORY;
        }

        pEp_member* new_mem = new_member(ident);
        new_mem->adopted = sqlite3_column_int(session->get_all_members, 2);
        member_list* new_node = new_memberlist(new_mem);
        if (!new_node)
            return PEP_OUT_OF_MEMORY;

        *member_list_next = new_node;
        member_list_next = &(new_node->next);
    }
    sqlite3_reset(session->get_all_members);

    member_list* curr = retval;

    for ( ; curr ; curr = curr->next) {
        if (!(curr->member && curr->member->ident))
            return PEP_UNKNOWN_ERROR; // FIXME, free
        status = update_identity(session, curr->member->ident);
    }

    *members = retval;

    return PEP_STATUS_OK;
}

PEP_STATUS retrieve_active_member_idents(
        PEP_SESSION session,
        pEp_identity* group_identity,
        identity_list** member_idents)
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (!session || !group_identity || !member_idents)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) || EMPTYSTR(group_identity->address))
        return PEP_ILLEGAL_VALUE;

    *member_idents = NULL;

    sqlite3_reset(session->get_active_members);
    sqlite3_bind_text(session->get_active_members, 1, group_identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_active_members, 2, group_identity->address, -1, SQLITE_STATIC);
    int result;

    identity_list* retval = NULL;
    identity_list** id_list_next = &retval;

    while ((result = sqlite3_step(session->get_active_members)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity((const char *) sqlite3_column_text(session->get_active_members, 1),
                NULL,(const char *) sqlite3_column_text(session->get_active_members, 0),
                NULL);
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_active_members);
            return PEP_OUT_OF_MEMORY;
        }

        identity_list* new_node = new_identity_list(ident);
        if (!new_node)
            return PEP_OUT_OF_MEMORY;

        *id_list_next = new_node;
        id_list_next = &(new_node->next);
    }
    sqlite3_reset(session->get_active_members);

    identity_list* curr = retval;

    for ( ; curr ; curr = curr->next) {
        if (!curr->ident)
            return PEP_UNKNOWN_ERROR; // FIXME, free
        status = update_identity(session, curr->ident);
    }

    *member_idents = retval;
    
    return PEP_STATUS_OK;
}

PEP_STATUS group_rating(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        PEP_rating *rating
) {

    PEP_STATUS status = PEP_STATUS_OK;
    if (!is_me(session, manager))
        return identity_rating(session, group_identity, rating);


    identity_list* active_members = NULL;

    status = retrieve_active_member_idents(session, group_identity, &active_members);

    if (status != PEP_STATUS_OK)
        return status;

    PEP_rating _rating = PEP_rating_fully_anonymous;

    if (active_members) {
        identity_list* curr;

        for (curr = active_members; curr; curr = curr->next) {
            PEP_rating tmp_rating = PEP_rating_undefined;
            status = identity_rating(session, group_identity, &tmp_rating);
            if (status != PEP_STATUS_OK)
                return status;  // FIXME: free

            if (tmp_rating < _rating)
                _rating = tmp_rating;
        }
    }
    else {
        _rating = PEP_rating_undefined; // ??? or group_identity? I dunno.
    }

    *rating = _rating;

    return PEP_STATUS_OK;
}

PEP_STATUS exists_group(
        PEP_SESSION session,
        pEp_identity* group_identity,
        bool* exists
) {

    PEP_STATUS status = PEP_STATUS_OK;

    sqlite3_reset(session->exists_group_entry);
    sqlite3_bind_text(session->exists_group_entry, 1, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_group_entry, 2, group_identity->user_id, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->exists_group_entry);

    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *exists = (sqlite3_column_int(session->exists_group_entry, 0) != 0);
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }

    sqlite3_reset(session->exists_group_entry);

    return status;
}

