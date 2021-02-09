// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "group.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "distribution_codec.h"
#include "map_asn1.h"
#include "baseprotocol.h"


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

static PEP_STATUS _set_membership_status(PEP_SESSION session,
                                            pEp_identity* group_identity,
                                            pEp_identity* as_member,
                                            bool active) {
    int result = 0;

    sqlite3_reset(session->set_group_member_status);

    sqlite3_bind_int(session->set_group_member_status, 1, active);
    sqlite3_bind_text(session->set_group_member_status, 2, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->set_group_member_status, 3, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->set_group_member_status, 4, as_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->set_group_member_status, 5, as_member->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->set_group_member_status);

    sqlite3_reset(session->set_group_member_status);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

static PEP_STATUS _set_own_status_joined(PEP_SESSION session,
                                            pEp_identity* group_identity,
                                            pEp_identity* as_member) {
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

PEP_STATUS get_group_manager(PEP_SESSION session,
                             pEp_identity* group_identity,
                             pEp_identity** manager) {
    if (!session || !group_identity || !manager ||
                    EMPTYSTR(group_identity->user_id) || EMPTYSTR(group_identity->address))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;

    sqlite3_reset(session->get_group_manager);

    sqlite3_bind_text(session->get_group_manager, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_group_manager, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->get_group_manager);

    if (result != SQLITE_ROW)
        status = PEP_GROUP_NOT_FOUND;
    else {
        *manager = new_identity((const char *) sqlite3_column_text(session->get_group_manager, 1),
                                NULL, (const char *) sqlite3_column_text(session->get_group_manager, 0),
                                NULL);
        if (!*manager)
            return PEP_OUT_OF_MEMORY;
    }
    sqlite3_reset(session->get_group_manager);
    return status;
}

PEP_STATUS is_group_active(PEP_SESSION session, pEp_identity* group_identity, bool* active) {
    if (!group_identity || EMPTYSTR(group_identity->address) || EMPTYSTR(group_identity->user_id) || !active)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    *active = false;

    sqlite3_reset(session->is_group_active);
    sqlite3_bind_text(session->is_group_active, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_group_active, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->is_group_active);

    switch (result) {
        case SQLITE_ROW: {
            *active = (sqlite3_column_int(session->is_group_active, 0) != 0);
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }

    sqlite3_reset(session->is_group_active);

    return status;
}

PEP_STATUS is_group_mine(PEP_SESSION session, pEp_identity* group_identity, bool* own_manager) {
    if (!own_manager)
        return PEP_ILLEGAL_VALUE;

    *own_manager = false;

    // Ok, we have a group ident. Someone ensure I'm the manager...
    pEp_identity* manager = NULL;
    PEP_STATUS status = get_group_manager(session, group_identity, &manager);
    if (status != PEP_STATUS_OK)
        return status;
    if (!manager)
        return PEP_GROUP_NOT_FOUND;

    if (is_me(session, manager))
        *own_manager = true;

    free_identity(manager);

    return PEP_STATUS_OK;
}
// group_identity MUST have been myself'd.
// Called only from create_group and PRESUMES group, group->identity (user_id and address),
// group->manager (user_id and address) are there AND VALIDATED. This is JUST the DB call factored out.
PEP_STATUS create_group_entry(PEP_SESSION session,
                              pEp_group* group) {
    pEp_identity* group_identity = group->group_identity;
    pEp_identity* manager = group->manager;

    int result = 0;

    sqlite3_reset(session->create_group);

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

// FIXME: group_ident_clone on error
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

    PEP_STATUS status = PEP_STATUS_OK;

    if (!group_identity->user_id || !is_me(session, group_identity)) {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        if (status != PEP_STATUS_OK)
            return status;

        free(group_identity->user_id);
        group_identity->user_id = own_id;
    }

    // We have an address, create a key for the group if needed
    status = myself(session, group_identity);
    if (status != PEP_STATUS_OK)
        return status;

    // Do we already have this group?
    bool already_exists = false;
    status = exists_group(session, group_identity, &already_exists);
    if (already_exists)
        return PEP_GROUP_EXISTS;

    // from here on out: group_identity still belongs to the caller. So we dup it.
    pEp_identity* group_ident_clone = identity_dup(group_identity);
    if (!group_ident_clone)
        return PEP_OUT_OF_MEMORY;

    // set it as a group_identity
    status = set_identity_flags(session, group_ident_clone, group_ident_clone->flags | PEP_idf_group_ident);
    if (status != PEP_STATUS_OK)
        return status;

    // update the manager ident
    if (is_me(session, manager))
        status = myself(session, manager);
    else
        status = update_identity(session, manager);
    if (status != PEP_STATUS_OK)
        return status;

    if (manager->flags & PEP_idf_group_ident)
        return PEP_ILLEGAL_VALUE;

    // Ok, we're ready to do DB stuff. Do some allocation:
    pEp_group* _group = new_group(group_ident_clone, manager, memberlist);
    if (!_group)
        return PEP_OUT_OF_MEMORY;

    // Before we start doing database stuff, also get current member info (yes, I realise
    // we're traversing the list twice.)
    member_list* curr_member = NULL;
    // Will bail if adding fails.
    for (curr_member = memberlist; curr_member && curr_member->member && curr_member->member->ident && status == PEP_STATUS_OK;
         curr_member = curr_member->next) {

        pEp_identity* member = curr_member->member->ident;

        if (is_me(session, member))
            status = myself(session, member);
        else
            status = update_identity(session, member);

        if (status != PEP_STATUS_OK)
            return status;
    }

    sqlite3_exec(session->db, "BEGIN TRANSACTION ;", NULL, NULL, NULL);

    status = create_group_entry(session, _group);

    if (status == PEP_STATUS_OK) {
        status = group_enable(session, group_ident_clone);
    }

    if (status == PEP_STATUS_OK) {
        curr_member = NULL;
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
                    status = group_add_member(session, group_ident_clone, member);
                    if (status == PEP_STATUS_OK) {
                        if (is_me(session, member)) {
                            status = add_own_membership_entry(session, _group, member);
                        }
                    }
                    if (status != PEP_STATUS_OK)
                        goto pEp_free;
                }
            }
        }
    }


    if (status != PEP_STATUS_OK) {
        sqlite3_exec(session->db, "ROLLBACK ;", NULL, NULL, NULL);
        goto pEp_free;
    }
    sqlite3_exec(session->db, "COMMIT ;", NULL, NULL, NULL);

    // Ok, mail em.
    if (is_me(session, manager)) {
        status = send_GroupCreate(session, _group);
    }
    // FIXME: What do we do with failure?

    if (group)
        *group = _group;
    else
        free_group(_group);

    return PEP_STATUS_OK;

pEp_free:
    free_group(_group);
    *group = NULL;
    return status;
}

// This presumes these values have been checked!!!!!!!!
PEP_STATUS add_own_membership_entry(PEP_SESSION session,
                                    pEp_group* group,
                                    pEp_identity* own_identity_recip) {
    if (!session || !group || !group->group_identity || !group->manager || !own_identity_recip)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group->group_identity->user_id) || EMPTYSTR(group->group_identity->address))
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group->manager->user_id) || EMPTYSTR(group->manager->address))
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(own_identity_recip->user_id) || EMPTYSTR(own_identity_recip->address))
        return PEP_ILLEGAL_VALUE;

    int result = 0;

    sqlite3_bind_text(session->add_own_membership_entry, 1, group->group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 2, group->group_identity->address, -1,
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
    sqlite3_bind_text(session->get_own_membership_status, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 2, group_identity->address, -1,
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

PEP_STATUS retrieve_own_membership_info_for_group_and_identity(PEP_SESSION session,
                                                     pEp_group* group,
                                                     pEp_identity* own_identity) {

    PEP_STATUS status = PEP_STATUS_OK;

    sqlite3_reset(session->retrieve_own_membership_info_for_group_and_ident);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 1, group->group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 2, group->group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 3, own_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 4, own_identity->address, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->retrieve_own_membership_info_for_group_and_ident);

    switch (result) {
        case SQLITE_ROW: {
            pEp_member* me_mem = new_member(own_identity);
            if (!me_mem)
                return PEP_OUT_OF_MEMORY;
            me_mem->adopted = sqlite3_column_int(session->retrieve_own_membership_info_for_group_and_ident, 0);
            member_list* memberlist = new_memberlist(me_mem);
            if (!memberlist)
                return PEP_OUT_OF_MEMORY;;

            group->members = memberlist;
            group->manager = new_identity((const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group_and_ident, 2),
                                                NULL,
                                                (const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group_and_ident, 1),
                                                NULL);
            if (!group->manager)
                return PEP_OUT_OF_MEMORY;
            group->active = sqlite3_column_int(session->retrieve_own_membership_info_for_group_and_ident, 3);
            break;
        }
        default:
            status = PEP_NO_MEMBERSHIP_STATUS_FOUND;
    }

    return status;
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

static PEP_STATUS _set_leave_group_status(PEP_SESSION session, pEp_identity* group_identity, pEp_identity* leaver) {

    sqlite3_reset(session->leave_group);

    sqlite3_bind_text(session->leave_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 3, leaver->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 4, leaver->address, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->leave_group);

    sqlite3_reset(session->leave_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_LEAVE_GROUP;
    else
        return PEP_STATUS_OK;
}

static PEP_STATUS _set_group_as_disabled(PEP_SESSION session, pEp_identity* group_identity) {
    int result = 0;

    sqlite3_reset(session->disable_group);

    sqlite3_bind_text(session->disable_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->disable_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    result = sqlite3_step(session->disable_group);

    sqlite3_reset(session->disable_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_DISABLE_GROUP;

    else
        return PEP_STATUS_OK;

}

static PEP_STATUS _retrieve_own_membership_info_for_group(PEP_SESSION session, pEp_identity* group_identity,
                                                          member_list** memberlist) {
    int result = 0;

    member_list* _mbr_list_head = NULL;
    member_list** _mbr_list_next = &_mbr_list_head;

    sqlite3_reset(session->retrieve_own_membership_info_for_group);

    sqlite3_bind_text(session->retrieve_own_membership_info_for_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    while ((result = sqlite3_step(session->retrieve_own_membership_info_for_group)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity((const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group, 1),
                                           NULL,(const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group, 0),
                                           NULL);
        assert(ident);

        // FIXME: better exit path, this is just to get it down
        if (ident == NULL) {
            sqlite3_reset(session->retrieve_own_membership_info_for_group);
            return PEP_OUT_OF_MEMORY;
        }
        pEp_member* member = new_member(ident);
        if (!member) {
            sqlite3_reset(session->retrieve_own_membership_info_for_group);
            return PEP_OUT_OF_MEMORY;
        }
        member->adopted = sqlite3_column_int(session->retrieve_own_membership_info_for_group, 2);

        *_mbr_list_next = new_memberlist(member);
        if (!(*_mbr_list_next)) {
            sqlite3_reset(session->retrieve_own_membership_info_for_group);
            return PEP_OUT_OF_MEMORY;
        }
        _mbr_list_next = &((*_mbr_list_next)->next);
    }

    sqlite3_reset(session->retrieve_own_membership_info_for_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_DISABLE_GROUP;
    else
        return PEP_STATUS_OK;

}

PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    status = _set_group_as_disabled(session, group_identity);
    if (status != PEP_STATUS_OK)
        return status;

    // If I'm the manager, then I have to send out the dissolution stuff and deactivate
    if (is_me(session, manager)) {
        status = revoke_key(session, group_identity->fpr, NULL);
        if (status != PEP_STATUS_OK)
            return status;

        // You'd better get all the group info here
        member_list* list = NULL;

        status = retrieve_active_member_list(session, group_identity, &list);
        if (status != PEP_STATUS_OK)
            return status;

        pEp_group* group = new_group(group_identity, manager, list);
        if (!list)
            return PEP_OUT_OF_MEMORY;

        status = send_GroupDissolve(session, group);
        if (status != PEP_STATUS_OK)
            return status; // fixme

        // deactivate members
        member_list* memb = group->members;

        while (memb && memb->member && memb->member->ident) {
            pEp_identity* memb_ident = memb->member->ident;
            if (EMPTYSTR(memb_ident->user_id) || EMPTYSTR(memb_ident->address))
                return PEP_UNKNOWN_ERROR;
            status = _set_membership_status(session, group_identity, memb->member->ident, false);
            memb = memb->next;
        }
        // We don't own the group_ident or manager that comes in here, so we need to set them to NULL.
        group->group_identity = NULL;
        group->manager = NULL;

        free_group(group);
    }
    else {
        // I'm not the manager. So I need to find the identities I have that
        // know about or have joined this group and tell them the fun is over
        member_list* my_group_idents = NULL;
        status = _set_group_as_disabled(session, group_identity);
        if (status != PEP_STATUS_OK)
            return status;

        // Ok, group is now not usable. Let's get our membership straight.
        status = _retrieve_own_membership_info_for_group(session, group_identity, &my_group_idents);

        if (status != PEP_STATUS_OK)
            return status;

        member_list* curr_member = my_group_idents;

        while (curr_member) {
            if (!curr_member->member)
                break; // ??
            pEp_identity* ident = curr_member->member->ident;
            if (!ident)
                break; // er... this should probably be an error, but given how we do lists, it's acceptable
            status = _set_leave_group_status(session, group_identity, ident);
            if (status != PEP_STATUS_OK)
                return status;

            curr_member = curr_member->next;
        }
    }

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

// Do we even want to use this function??? FIXME
//PEP_STATUS group_remove_member(
//        PEP_SESSION session,
//        pEp_identity *group_identity,
//        pEp_identity *group_member
//) {
//    bool exists = false;
//    PEP_STATUS status = exists_group(session, group_identity, &exists);
//    if (status != PEP_STATUS_OK)
//        return status;
//
//    if (!exists)
//        return PEP_GROUP_NOT_FOUND;
//
//    return _set_membership_status(session, group_identity, group_member, false);
//}

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

PEP_STATUS retrieve_active_member_list(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** mbr_list)
{
    PEP_STATUS status = PEP_STATUS_OK;

    if (!session || !group_identity || !mbr_list)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) || EMPTYSTR(group_identity->address))
        return PEP_ILLEGAL_VALUE;

    *mbr_list = NULL;

    sqlite3_reset(session->get_active_members);
    sqlite3_bind_text(session->get_active_members, 1, group_identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_active_members, 2, group_identity->address, -1, SQLITE_STATIC);
    int result;

    member_list* retval = NULL;
    member_list** mbr_list_next = &retval;

    while ((result = sqlite3_step(session->get_active_members)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity((const char *) sqlite3_column_text(session->get_active_members, 1),
                NULL,(const char *) sqlite3_column_text(session->get_active_members, 0),
                NULL);
        assert(ident);
        if (ident == NULL) {
            sqlite3_reset(session->get_active_members);
            return PEP_OUT_OF_MEMORY;
        }

        pEp_member* member = new_member(ident);
        if (!member)
            return PEP_OUT_OF_MEMORY;

        member_list* new_node = new_memberlist(member);
        if (!new_node)
            return PEP_OUT_OF_MEMORY;

        new_node->member->adopted = true;

        *mbr_list_next = new_node;
        mbr_list_next = &(new_node->next);
    }
    sqlite3_reset(session->get_active_members);

    member_list* curr = retval;

    for ( ; curr && curr->member && curr->member->ident; curr = curr->next) {
        if (!curr->member->ident)
            return PEP_UNKNOWN_ERROR; // FIXME, free
        status = update_identity(session, curr->member->ident);
    }

    *mbr_list = retval;
    
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


    member_list* active_members = NULL;

    status = retrieve_active_member_list(session, group_identity, &active_members);

    if (status != PEP_STATUS_OK)
        return status;

    PEP_rating _rating = PEP_rating_fully_anonymous;

    if (active_members) {
        member_list* curr;

        for (curr = active_members; curr; curr = curr->next) {
            if (!(curr->member) && curr->next != NULL)
                return PEP_ILLEGAL_VALUE;

            if (!(curr->member->ident))
                return PEP_ILLEGAL_VALUE;

            PEP_rating tmp_rating = PEP_rating_undefined;

            status = identity_rating(session, curr->member->ident, &tmp_rating);
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
    sqlite3_bind_text(session->exists_group_entry, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_group_entry, 2, group_identity->address, -1,
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


// member list is updated PRIOR to call.
PEP_STATUS send_GroupCreate(PEP_SESSION session, pEp_group* group) {
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    if (!session || !group || !group->group_identity || !group->manager)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group->group_identity->user_id) ||
        EMPTYSTR(group->group_identity->address)  ||
        EMPTYSTR(group->manager->user_id) ||
        EMPTYSTR(group->manager->address)) {
        return PEP_ILLEGAL_VALUE;
    }

    if (!is_me(session, group->manager))
        return PEP_ILLEGAL_VALUE;

    message* enc_msg = NULL;

    // Ok, let's get the payload set up, because we can duplicate this for each message.
    Distribution_t* outdist = (Distribution_t *) calloc(1, sizeof(Distribution_t));
    if (!outdist)
        return PEP_OUT_OF_MEMORY;

    outdist->present = Distribution_PR_managedgroup;
    outdist->choice.managedgroup.present = ManagedGroup_PR_groupCreate;
    GroupCreate_t* gc = &(outdist->choice.managedgroup.choice.groupCreate);

    if (!Identity_from_Struct(group->group_identity, &gc->groupIdentity)) {
        free(gc);
        return PEP_OUT_OF_MEMORY;
    }

    if (!Identity_from_Struct(group->manager, &gc->manager)) {
        free(gc);
        return PEP_OUT_OF_MEMORY;
    }

    // Man, I hope this is it.
    char *_data;
    size_t _size;
    PEP_STATUS status = encode_Distribution_message(outdist, &_data, &_size);
    if (status != PEP_STATUS_OK)
        return status; // FIXME - memory

    // Ok, for every member in the member list, send away.
    // (We'll copy in for now. It's small and quick.)
    member_list* curr_invite = NULL;

    message* msg = NULL;

    char* key_material_priv = NULL;
    size_t key_material_size = 0;

    status = export_secret_key(session, group->group_identity->fpr, &key_material_priv, &key_material_size);
    if (status != PEP_STATUS_OK)
        return status;
    if (key_material_size == 0 || !key_material_priv)
        return PEP_UNKNOWN_ERROR;

    for (curr_invite = group->members; curr_invite && curr_invite->member && curr_invite->member->ident; curr_invite = curr_invite->next) {
        pEp_identity* recip = curr_invite->member->ident; // This will be duped in base_prepare_message
        PEP_rating recip_rating;
        status = identity_rating(session, recip, &recip_rating);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
        if (recip_rating < PEP_rating_reliable)
            continue;

        char* data_copy = (char*)malloc(_size);
        if (!data_copy)
            return PEP_OUT_OF_MEMORY;
        memcpy(data_copy, _data, _size);

        status = base_prepare_message(session, group->manager, recip, BASE_DISTRIBUTION,
                                      data_copy, _size, group->manager->fpr, &msg);
        if (status != PEP_STATUS_OK)
            goto pEp_error;

        if (!msg) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_error;
        }
        if (!msg->attachments) {
            status = PEP_UNKNOWN_ERROR;
            goto pEp_error;
        }

        char* key_material_copy = malloc(key_material_size);
        if (!key_material_copy)
            return PEP_OUT_OF_MEMORY;

        memcpy(key_material_copy, key_material_priv, key_material_size);

        bloblist_add(msg->attachments, key_material_copy, key_material_size, "application/pgp-keys",
                                                                             "file://pEpkey_group_priv.asc");

        // encrypt this baby and get out
        // extra keys???
        status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0); // FIXME

        if (status != PEP_STATUS_OK)
            goto pEp_error;

        _add_auto_consume(enc_msg);

        // insert into queue
        status = session->messageToSend(enc_msg);

        if (status != PEP_STATUS_OK)
            goto pEp_error;

        free_message(msg);
        msg = NULL;
    }

pEp_error:
    return status;

}

// This ALREADY has a list of active members attached to the group by
// group_dissolve. So don't do it again.
PEP_STATUS send_GroupDissolve(PEP_SESSION session, pEp_group* group) {
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    if (!session || !group || !group->group_identity || !group->manager)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group->group_identity->user_id) ||
        EMPTYSTR(group->group_identity->address)  ||
        EMPTYSTR(group->manager->user_id) ||
        EMPTYSTR(group->manager->address)) {
        return PEP_ILLEGAL_VALUE;
    }

    if (!is_me(session, group->manager))
        return PEP_ILLEGAL_VALUE;

    message* enc_msg = NULL;

    // Ok, let's get the payload set up, because we can duplicate this for each message.
    Distribution_t* outdist = (Distribution_t *) calloc(1, sizeof(Distribution_t));
    if (!outdist)
        return PEP_OUT_OF_MEMORY;

    outdist->present = Distribution_PR_managedgroup;
    outdist->choice.managedgroup.present = ManagedGroup_PR_groupDissolve;
    GroupDissolve_t* gd = &(outdist->choice.managedgroup.choice.groupDissolve);

    if (!Identity_from_Struct(group->group_identity, &gd->groupIdentity)) {
        free(gd);
        return PEP_OUT_OF_MEMORY;
    }

    if (!Identity_from_Struct(group->manager, &gd->manager)) {
        free(gd);
        return PEP_OUT_OF_MEMORY;
    }

    // Man, I hope this is it.
    char *_data;
    size_t _size;
    PEP_STATUS status = encode_Distribution_message(outdist, &_data, &_size);
    if (status != PEP_STATUS_OK)
        return status; // FIXME - memory

    // Ok, for every member in the active member list, which came in attached to the group argument, send away.
    member_list* list = group->members;
    if (!list)
        return PEP_STATUS_OK; // no members to send to

    member_list* curr_mem = NULL;

    message* msg = NULL;

    char* key_material= NULL;
    size_t key_material_size = 0;

    // Get revocation
    status = export_key(session, group->group_identity->fpr, &key_material, &key_material_size);
    if (status != PEP_STATUS_OK)
        return status;
    if (key_material_size == 0 || !key_material)
        return PEP_UNKNOWN_ERROR;

    for (curr_mem = list; curr_mem && curr_mem->member && curr_mem->member->ident; curr_mem = curr_mem->next) {
        pEp_identity* recip = curr_mem->member->ident; // This will be duped in base_prepare_message
        PEP_rating recip_rating;
        status = identity_rating(session, recip, &recip_rating);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
        if (recip_rating < PEP_rating_reliable)
            continue;

        char* data_copy = (char*)malloc(_size);
        if (!data_copy)
            return PEP_OUT_OF_MEMORY;
        memcpy(data_copy, _data, _size);

        status = base_prepare_message(session, group->manager, recip, BASE_DISTRIBUTION,
                                      data_copy, _size, group->manager->fpr, &msg);
        if (status != PEP_STATUS_OK)
            goto pEp_error;

        if (!msg) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_error;
        }
        if (!msg->attachments) {
            status = PEP_UNKNOWN_ERROR;
            goto pEp_error;
        }

        char* key_material_copy = malloc(key_material_size);
        if (!key_material_copy)
            return PEP_OUT_OF_MEMORY;

        memcpy(key_material_copy, key_material, key_material_size);

        bloblist_add(msg->attachments, key_material_copy, key_material_size, "application/pgp-keys",
                                                                             "file://pEpkey_group_revoke.asc");

        // encrypt this baby and get out
        // extra keys???
        status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0); // FIXME

        if (status != PEP_STATUS_OK)
            goto pEp_error;

        _add_auto_consume(enc_msg);

        // insert into queue
        status = session->messageToSend(enc_msg);

        if (status != PEP_STATUS_OK)
            goto pEp_error;

        free_message(msg);
        msg = NULL;
    }

pEp_error:
    return status;

}

PEP_STATUS send_GroupAdopted(PEP_SESSION session, pEp_identity* group_identity, pEp_identity* from) {

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* manager = NULL;
    message* enc_msg = NULL;

    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    if (!session || !group_identity || !from)
        return PEP_ILLEGAL_VALUE;

    if (EMPTYSTR(group_identity->user_id) ||
        EMPTYSTR(group_identity->address)  ||
        EMPTYSTR(from->user_id) ||
        EMPTYSTR(from->address)) {
        return PEP_ILLEGAL_VALUE;
    }

    if (!is_me(session, group_identity))
        status = update_identity(session, group_identity);
    else
        status = _myself(session, group_identity, false, false, false, true);

    if (status != PEP_STATUS_OK)
        return status;
    else if (!(is_me(session, group_identity) && group_identity->flags & PEP_idf_group_ident)) {
        return PEP_ILLEGAL_VALUE;
    }

    // Get the manager

    status = get_group_manager(session, group_identity, &manager);
    if (status != PEP_STATUS_OK)
        return status;
    else if (!manager)
        return PEP_OUT_OF_MEMORY;
    else if (EMPTYSTR(manager->address) || EMPTYSTR(manager->user_id)) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }

    // ?? Is this really necessary? It's an internal call. Well, anything can mess up, no?
    if (is_me(session, manager))
        return PEP_ILLEGAL_VALUE;

    status = update_identity(session, manager);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    // ??

    // Ok, let's get the payload set up.
    Distribution_t* outdist = (Distribution_t *) calloc(1, sizeof(Distribution_t));
    if (!outdist)
        return PEP_OUT_OF_MEMORY;

    outdist->present = Distribution_PR_managedgroup;
    outdist->choice.managedgroup.present = ManagedGroup_PR_groupAdopted;
    GroupAdopted_t* ga = &(outdist->choice.managedgroup.choice.groupAdopted);

    if (!Identity_from_Struct(group_identity, &ga->groupIdentity)) {
        free(ga);
        return PEP_OUT_OF_MEMORY;
    }

    if (!Identity_from_Struct(from, &ga->member)) {
        free(ga);
        return PEP_OUT_OF_MEMORY;
    }

    // Man, I hope this is it.
    char *_data;
    size_t _size;
    status = encode_Distribution_message(outdist, &_data, &_size);
    if (status != PEP_STATUS_OK)
        return status; // FIXME - memory

    pEp_identity* recip = manager; // This will be duped in base_prepare_message
    PEP_rating recip_rating;
    status = identity_rating(session, recip, &recip_rating);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    if (recip_rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // ??? FIXME

    message* msg = NULL;

    status = base_prepare_message(session, from, recip, BASE_DISTRIBUTION,
                                  _data, _size, from->fpr, &msg);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (!msg) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }
    if (!msg->attachments) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }

    // encrypt this baby and get out
    // extra keys???
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0); // FIXME

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    _add_auto_consume(enc_msg);

    // insert into queue
    status = session->messageToSend(enc_msg);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    free_message(msg);
    msg = NULL;

pEp_free:
    free_identity(manager);
    return status;

}

PEP_STATUS receive_GroupCreate(PEP_SESSION session, message* msg, PEP_rating rating, GroupCreate_t* gc) {
    PEP_STATUS status = PEP_STATUS_OK;
    if (rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // Find better error

    if (!msg)
        return PEP_ILLEGAL_VALUE;

    // Make sure everything's there are enforce exactly one recip
    if (!gc || !msg->to || !msg->to->ident || msg->to->next)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // this will be hard without address aliases.

    // We will probably always have to do this, but if something changes externally we need this check.
    if (!msg->to->ident->me) {
        status = update_identity(session, msg->to->ident);
        if (status != PEP_STATUS_OK)
            return status;
    }

    if (!is_me(session, msg->to->ident))
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    pEp_identity* group_identity = Identity_to_Struct(&(gc->groupIdentity), NULL);
    if (!group_identity)
        return PEP_UNKNOWN_ERROR; // we really don't know why

    pEp_identity* manager = Identity_to_Struct(&(gc->manager), NULL);
    if (!manager)
        return PEP_UNKNOWN_ERROR;

    free(manager->user_id);
    manager->user_id = NULL;
    free(group_identity->user_id);
    group_identity->user_id = NULL;

    status = update_identity(session, manager);
    if (!manager->fpr) // at some point, we can require this to be the sender fpr I think - FIXME
        return PEP_KEY_NOT_FOUND;

    // Ok then - let's do this:
    // First, we need to ensure the group_ident has an own ident instead
    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);
    if (status != PEP_STATUS_OK || !own_id) {
        free(own_id);
        return status;
    }
    group_identity->user_id = own_id;

    // Ok, let's ensure we HAVE the key for this group:
    stringlist_t* keylist = NULL;
    status = find_private_keys(session, group_identity->fpr, &keylist);

    if (status != PEP_STATUS_OK)
        return status;

    if (!keylist)
        return PEP_KEY_NOT_FOUND;

    status = set_own_key(session, group_identity, group_identity->fpr);

    if (status != PEP_STATUS_OK)
        return status;

    pEp_member* member = new_member(identity_dup(msg->to->ident));
    if (!member || !member->ident)
        return PEP_OUT_OF_MEMORY;

    member_list* list = new_memberlist(member);
    if (!list)
        return PEP_OUT_OF_MEMORY;

    pEp_group* group = NULL;
    status = group_create(session, group_identity, manager, list, &group);

    if (status != PEP_STATUS_OK) {
        free_group(group);
        return status;
    }

    status = add_own_membership_entry(session, group, msg->to->ident);

    free_group(group);
    return status;
}

PEP_STATUS receive_GroupDissolve(PEP_SESSION session, message* msg, PEP_rating rating, GroupDissolve_t* gd) {
    PEP_STATUS status = PEP_STATUS_OK;

    if (rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // Find better error

    if (!msg)
        return PEP_ILLEGAL_VALUE;

    // Make sure everything's there are enforce exactly one recip
    if (!gd || !msg->to || !msg->to->ident || msg->to->next)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // We will probably always have to do this, but if something changes externally we need this check.
    if (!msg->to->ident->me) {
        status = update_identity(session, msg->to->ident);
        if (status != PEP_STATUS_OK)
            return status;
    }

    // this will be hard without address aliases
    if (!is_me(session, msg->to->ident))
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    pEp_identity* own_identity = msg->to->ident;

    pEp_identity* group_identity = Identity_to_Struct(&(gd->groupIdentity), NULL);
    if (!group_identity)
        return PEP_UNKNOWN_ERROR; // we really don't know why

    pEp_identity* manager = Identity_to_Struct(&(gd->manager), NULL);
    if (!manager)
        return PEP_UNKNOWN_ERROR;

    free(manager->user_id);
    manager->user_id = NULL;
    status = update_identity(session, manager);
    if (status != PEP_STATUS_OK)
        return status;

    if (is_me(session, manager)) {
        // if this is from me, I should never have received this message, so we ignore it
        return PEP_STATUS_OK;
    }

    // FIXME - we'll have to check that it matches A sender key, not "THE" sender key.
    if (!manager->fpr)
        return PEP_KEY_NOT_FOUND;

    // N.B. This check is sort of a placeholder - this will change once it is possible
    // for the signer to NOT be the manager of the group. For now, we check the claim against
    // the sender and the known database manager against the sender.

    // It would be stupid to lie here, but form and all.. FIXME: Change when signature delivery is
    // implemented as in https://dev.pep.foundation/Engine/GroupEncryption#design - this will no longer
    // be sufficient or entirely correct
    if (strcmp(manager->fpr, msg->_sender_fpr) != 0)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
    if (strcmp(manager->address, msg->from->address) != 0) // ???? FIXME
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // Update group identity id
    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);
    if (!status || !own_id) {
        free(own_id);
        return status;
    }
    free(group_identity->user_id);
    group_identity->user_id = own_id;

    // The real check, for now. Later, the check will be manager->fpr against
    // DB fpr.
    // Shell, not full info - I guess we've verified the manager claim here
    pEp_group* group = new_group(group_identity, manager, NULL);

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_identity);
    if (status != PEP_STATUS_OK)
        return status;

    // Ok, so we have a group with this manager and we have received info about it from our own
    // membership info. We've at least been invited.

    // Ok then - let's do this:

    // set group to inactive and our own membership to non-participant
    status = group_dissolve(session, group_identity, manager);

    // Ok, database is set. Now for the keys:

    // Ok, let's ensure we HAVE the key for this group:
    stringlist_t* keylist = NULL;
    status = find_private_keys(session, group_identity->fpr, &keylist);

    if (status != PEP_STATUS_OK)
        return status;

    if (!keylist)
        return PEP_KEY_NOT_FOUND;

    // It should have been revoked on message import. Was it?
    bool revoked = false;
    status = key_revoked(session, group_identity->fpr, &revoked);

    if (!revoked)
        return PEP_UNKNOWN_ERROR; // what do we do here? FIXME.

    // FIXME: More to do?
    return status;
}

static PEP_STATUS is_invited_group_member(PEP_SESSION session, pEp_identity* group_identity,
                                          pEp_identity* member, bool* is_member) {
    if (!session || !is_member)
        return PEP_ILLEGAL_VALUE;

    if (!group_identity || EMPTYSTR(group_identity->user_id) || EMPTYSTR(group_identity->address))
        return PEP_ILLEGAL_VALUE;

    if (!member || EMPTYSTR(member->user_id) || EMPTYSTR(member->address))
        return PEP_ILLEGAL_VALUE;
    
    sqlite3_bind_text(session->is_invited_group_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_invited_group_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_invited_group_member, 3, member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_invited_group_member, 4, member->address, -1,
                      SQLITE_STATIC);

    int result = sqlite3_step(session->is_invited_group_member);

    if (result != SQLITE_ROW)
        return PEP_UNKNOWN_DB_ERROR;
    else
        *is_member = sqlite3_column_int(session->is_invited_group_member, 0);

    sqlite3_reset(session->is_invited_group_member);

    return PEP_STATUS_OK;
}

PEP_STATUS receive_GroupAdopted(PEP_SESSION session, message* msg, PEP_rating rating, GroupAdopted_t* ga) {
    PEP_STATUS status = PEP_STATUS_OK;

    if (rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // Find better error

    if (!msg)
        return PEP_ILLEGAL_VALUE;

    // Make sure everything's there are enforce exactly one recip
    if (!ga || !msg->to || !msg->to->ident || msg->to->next)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // We will probably always have to do this, but if something changes externally we need this check.
    if (!msg->to->ident->me) {
        status = update_identity(session, msg->to->ident);
        if (status != PEP_STATUS_OK)
            return status;
    }

    // this will be hard without address aliases
    if (!is_me(session, msg->to->ident))
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    pEp_identity* own_identity = msg->to->ident;

    pEp_identity* group_identity = Identity_to_Struct(&(ga->groupIdentity), NULL);
    if (!group_identity)
        return PEP_UNKNOWN_ERROR; // we really don't know why

    pEp_identity* member = Identity_to_Struct(&(ga->member), NULL);
    if (!member)
        return PEP_UNKNOWN_ERROR;

    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);
    if (status != PEP_STATUS_OK || EMPTYSTR(own_id))
        return PEP_UNKNOWN_ERROR;

    // is this even our group? If not, ignore.
    pEp_identity* db_group_ident = NULL;
    status = get_identity(session, group_identity->address, own_id, &db_group_ident);
    if (status != PEP_STATUS_OK)
        return status;

    // Fixme, free above
    if (!db_group_ident)
        return PEP_CANNOT_FIND_IDENTITY;

    // There's nothing in the group_identity we care about actually other than the address, so free and replace
    free_identity(group_identity);
    group_identity = db_group_ident;

    bool is_mine = NULL;
    status = is_group_mine(session, group_identity, &is_mine);

    if (status != PEP_STATUS_OK)
        return status;

    if (!is_mine)
        return PEP_STATUS_OK; // Ignore? FIXME

    // is this even someone we invited? If not, ignore.
    bool invited = false;

    // Ok, first off, the user_id will be wrong.
    free(member->user_id);
    member->user_id = NULL;
    status = update_identity(session, member);
    if (status != PEP_STATUS_OK)
        return status; // FIXME - please sort out memory!!!

    status = is_invited_group_member(session, group_identity, member, &invited);
    if (status != PEP_STATUS_OK)
        return status;

    if (!invited)
        return PEP_STATUS_OK; // Nice try, NSA Bob!

    // Ok. So. Do we need to check sender's FPR? I think we do.
    // It would be stupid to lie here, but form and all.. FIXME: Change when signature delivery is
    // implemented as in https://dev.pep.foundation/Engine/GroupEncryption#design - this will no longer
    // be sufficient or entirely correct
    if (strcmp(member->fpr, msg->_sender_fpr) != 0)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
    if (strcmp(member->address, msg->from->address) != 0) // ???? FIXME
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // Ok, we invited them. Set their status to "joined".
    status = _set_membership_status(session, group_identity, member, true);

    return status;

    // FIXME: free stuff
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
    status = send_GroupAdopted(session, group_identity, as_member);
    if (status != PEP_STATUS_OK)
        return status;

    status = _set_own_status_joined(session, group_identity, as_member);

    return PEP_STATUS_OK;
}


PEP_STATUS receive_managed_group_message(PEP_SESSION session, message* msg, PEP_rating rating, Distribution_t* dist) {
    if (!session || !msg || !msg->_sender_fpr || !dist)
        return PEP_ILLEGAL_VALUE;

//    char* sender_fpr = msg->_sender_fpr;
    switch (dist->choice.managedgroup.present) {
        case ManagedGroup_PR_groupCreate:
            return receive_GroupCreate(session, msg, rating, &(dist->choice.managedgroup.choice.groupCreate));
        case ManagedGroup_PR_groupDissolve:
            return receive_GroupDissolve(session, msg, rating, &(dist->choice.managedgroup.choice.groupDissolve));
        case ManagedGroup_PR_groupAdopted:
            return receive_GroupAdopted(session, msg, rating, &(dist->choice.managedgroup.choice.groupAdopted));
            break;
        default:
            return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
    }
    return PEP_STATUS_OK;
}

PEP_STATUS retrieve_group_info(PEP_SESSION session, pEp_identity* group_identity, pEp_group** group_info) {
    if (!session || !group_identity || EMPTYSTR(group_identity->address) || !group_info)
        return PEP_ILLEGAL_VALUE;

    pEp_group* group = NULL;
    pEp_identity* manager = NULL;
    member_list* members = NULL;

    PEP_STATUS status = PEP_STATUS_OK;
    *group_info = NULL;

    status = _myself(session, group_identity, false, false, false, true);

    if (status != PEP_STATUS_OK)
        return status;

    status = retrieve_full_group_membership(session, group_identity, &members);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = get_group_manager(session, group_identity, &manager);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    pEp_identity* group_ident_clone = identity_dup(group_identity);
    if (!group_ident_clone)
        return PEP_OUT_OF_MEMORY;

    group = new_group(group_ident_clone, manager, members);
    if (!group)
        return PEP_OUT_OF_MEMORY;

    bool active = false;
    status = is_group_active(session, group_identity, &active);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    group->active = active;
    *group_info = group;

    return status;

pEp_error:
    if (!group) {
        free_memberlist(members);
        free_identity(manager);
    }
    else {
        group->group_identity = NULL; // input belongs to caller in case of error
        free_group(group);
    }
    return status;
}

