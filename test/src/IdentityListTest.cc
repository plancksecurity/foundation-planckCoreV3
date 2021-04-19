// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include "test_util.h"

#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "platform.h"

#include "identity_list.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for IdentityListTest
    class IdentityListTest : public ::testing::Test {
        protected:    
            int test_identity_equals(pEp_identity* val1, pEp_identity* val2) {
                assert(val1 != nullptr);
                assert(val2 != nullptr);
                assert(val1->address != nullptr);
                assert(val2->address != nullptr);
                assert(val1->fpr != nullptr);
                assert(val2->fpr != nullptr);
                assert(val1->username != nullptr);
                assert(val2->username != nullptr);
                return((strcmp(val1->address, val2->address) == 0) && (strcmp(val1->fpr, val2->fpr) == 0)
                    && (strcmp(val1->username, val2->username) == 0) && (val1->comm_type == val2->comm_type)
                    && (val1->lang[0] == val2->lang[0]) && (val1->lang[1] == val2->lang[1])
                    && (val1->lang[2] == val2->lang[2]) && (val1->me == val2->me));
            }
    };

}  // namespace


TEST_F(IdentityListTest, check_identity_list) {

    pEp_identity* id1 = new_identity(
        "leon.schumacher@digitalekho.com",
        "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
        "23",
        "Leon Schumacher"
    );
    id1->comm_type = PEP_ct_pEp;

    pEp_identity* id2 = new_identity(
        "krista@kgrothoff.org",
        "62D4932086185C15917B72D30571AFBCA5493553",
        "42",
        "Krista Bennett Grothoff"
    );

    id2->comm_type = PEP_ct_OpenPGP;

    pEp_identity* id3 = new_identity(
        "krista@pep-project.org",
        "51BF42D25BB5B154D71BF6CD3CF25B776D149247",
        "10",
        "Krista Grothoff"
    );

    id3->comm_type = PEP_ct_OTR;

    pEp_identity* id4 = new_identity(
        "papa@smurf.lu",
        "00001111222233334444555566667777DEADBEEF",
        "667",
        "Papa Smurf"
    );

    id4->comm_type = PEP_ct_key_b0rken;

    pEp_identity* id_arr[4] = {id1, id2, id3, id4};

    int i;

    output_stream << "creating one-element identity_list...\n";

    pEp_identity* new_id = identity_dup(id1);
    ASSERT_NOTNULL(new_id);
    identity_list* idlist = new_identity_list(new_id);
    ASSERT_NOTNULL(idlist->ident);
    ASSERT_TRUE(test_identity_equals(id1, idlist->ident));
    ASSERT_NULL(idlist->next);
    output_stream << "one-element identity_list created, next element is NULL\n\n";

    output_stream << "duplicating one-element list...\n";
    identity_list* duplist = identity_list_dup(idlist);
    pEp_identity* srcid = idlist->ident;
    pEp_identity* dstid = duplist->ident;
    ASSERT_NOTNULL(dstid);
    ASSERT_TRUE(test_identity_equals(srcid, dstid));
    ASSERT_NE(srcid->address, dstid->address);   // test deep copies
    ASSERT_NE(srcid->fpr, dstid->fpr);
    ASSERT_NE(srcid->username, dstid->username);
    ASSERT_NULL(duplist->next);
    output_stream << "one-element identity_list duplicated.\n\n";

    output_stream << "freeing identity_lists...\n";
    free_identity_list(idlist); // will free srcid
    free_identity_list(duplist);
    idlist = NULL;
    duplist = NULL;
    srcid = NULL;

    identity_list* p;
    output_stream << "\ncreating four-element list...\n";
    idlist = identity_list_add(idlist, identity_dup(id_arr[0]));
    for (i = 1; i < 4; i++) {
        p = identity_list_add(idlist, identity_dup(id_arr[i]));
        ASSERT_NOTNULL(p);
    }

    p = idlist;

    for (i = 0; i < 4; i++) {
        ASSERT_NOTNULL(p);

        srcid = p->ident;
        ASSERT_NOTNULL(srcid);

        ASSERT_TRUE(test_identity_equals(srcid, id_arr[i]));
        ASSERT_NE(srcid->address , id_arr[i]->address);   // test deep copies
        ASSERT_NE(srcid->fpr , id_arr[i]->fpr);
        ASSERT_NE(srcid->username , id_arr[i]->username);

        p = p->next;
    }
    ASSERT_NULL(p );

    output_stream << "\nduplicating four-element list...\n\n";
    duplist = identity_list_dup(idlist);

    p = idlist;
    identity_list* dup_p = duplist;

    while (dup_p) {
        srcid = p->ident;
        dstid = dup_p->ident;

        ASSERT_NOTNULL(dstid);

        ASSERT_TRUE(test_identity_equals(srcid, dstid));

        ASSERT_NE(srcid , dstid);   // test deep copies
        ASSERT_NE(srcid->address , dstid->address);   // test deep copies
        ASSERT_NE(srcid->fpr , dstid->fpr);
        ASSERT_NE(srcid->username , dstid->username);

        i++;
        p = p->next;

        dup_p = dup_p->next;
        ASSERT_EQ((p == NULL), (dup_p == NULL));
    }
    output_stream << "\nfour-element identity_list successfully duplicated.\n\n";

    output_stream << "freeing identity_lists...\n";
    free_identity_list(idlist); // will free srcid
    free_identity_list(duplist);
    idlist = NULL;
    duplist = NULL;

    output_stream << "done.\n";
}
