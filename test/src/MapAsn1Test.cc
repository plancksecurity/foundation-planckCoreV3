// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <iostream>
#include <string>
#include <cstring>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "map_asn1.h"
#include "message_codec.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MapAsn1Test
    class MapAsn1Test : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            MapAsn1Test() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MapAsn1Test() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NOTNULL(engine);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NOTNULL(engine->session);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the MapAsn1Test suite.

    };

}  // namespace


TEST_F(MapAsn1Test, check_map_asn1) {

    output_stream << "creating new identity...\n";

    pEp_identity *ident1 = new_identity("vb@dingens.org",
            "DB4713183660A12ABAFA7714EBE90D44146F62F4", "42", "Volker Birk");
    ASSERT_NOTNULL(ident1);
    ident1->lang[0] = 'd';
    ident1->lang[1] = 'e';
    ident1->comm_type = PEP_ct_pEp;

    output_stream << "converting identity to ASN.1...\n";

    Identity_t *ident_asn1 = Identity_from_Struct(ident1, NULL);
    ASSERT_NOTNULL(ident_asn1);

    output_stream << "converting identity from ASN.1...\n";

    pEp_identity *ident2 = Identity_to_Struct(ident_asn1, NULL);
    ASSERT_NOTNULL(ident2);

    ASSERT_STREQ(ident1->address,ident2->address);
    ASSERT_STREQ(ident1->fpr,ident2->fpr);
    ASSERT_STREQ(ident1->user_id,ident2->user_id);
    ASSERT_STREQ(ident1->username,ident2->username);
    ASSERT_EQ(ident2->comm_type, PEP_ct_pEp);
    ASSERT_STREQ(ident2->lang,"de");

    output_stream << "freeing identities...\n";

    asn_DEF_Identity.free_struct(&asn_DEF_Identity, ident_asn1, 0);
    free_identity(ident1);
    free_identity(ident2);
}

TEST_F(MapAsn1Test, check_map_asn1_message) {
    output_stream << "testing ASN1Message...\n";

    message *msg = new_message(PEP_dir_outgoing);
    msg->id = strdup("423");
    msg->shortmsg = strdup("hello, world");
    msg->longmsg = strdup("long message");
    msg->longmsg_formatted = strdup("<p>long message</p>");
    msg->attachments = new_bloblist(strdup("blob"), 5, "text/plain", "test.txt");
    bloblist_add(msg->attachments, strdup("bla"), 4, "application/octet-stream", "data.dat");
    msg->sent = new_timestamp(23);
    msg->recv = new_timestamp(42);
    msg->from = new_identity("alice@mail.com", "2342234223422342", "23", "Alice Miller");
    msg->from->comm_type = PEP_ct_pEp;
    msg->from->lang[0] = 'd'; msg->from->lang[1] = 'e';
    msg->to = new_identity_list(new_identity("bob@mail.com", "4223422342234223", "42", "Bob Smith"));
    identity_list_add(msg->to, new_identity("alice@mail.com", "2342234223422342", "23", "Alice Miller"));
    msg->recv_by = new_identity("bob@mail.com", "4223422342234223", "42", "Bob Smith");
    msg->cc = new_identity_list(new_identity("bob@mail.com", "4223422342234223", "42", "Bob Smith"));
    identity_list_add(msg->cc, new_identity("alice@mail.com", "2342234223422342", "23", "Alice Miller"));
    msg->bcc = new_identity_list(new_identity("bob@mail.com", "4223422342234223", "42", "Bob Smith"));
    identity_list_add(msg->bcc, new_identity("alice@mail.com", "2342234223422342", "23", "Alice Miller"));
    msg->reply_to = new_identity_list(new_identity("bob@mail.com", "4223422342234223", "42", "Bob Smith"));
    identity_list_add(msg->reply_to, new_identity("alice@mail.com", "2342234223422342", "23", "Alice Miller"));
    msg->in_reply_to = new_stringlist("23234242");
    stringlist_add(msg->in_reply_to, "323234242");
    msg->references = new_stringlist("23234242");
    stringlist_add(msg->references , "323234242");
    msg->keywords = new_stringlist("something");
    stringlist_add(msg->keywords, "else");
    msg->comments = strdup("hello there");
    msg->opt_fields = new_stringpair_list(new_stringpair("key", "value"));
    stringpair_list_add(msg->opt_fields, new_stringpair("otherkey", "othervalue"));
    msg->_sender_fpr = strdup("2342234223422342");

    ASN1Message_t *pm = ASN1Message_from_message(msg, NULL, false, 1024);

    char *data = NULL;
    size_t data_size = 0;
    PEP_STATUS status = encode_ASN1Message_message(pm, &data, &data_size);
    ASSERT_EQ(status, PEP_STATUS_OK);

    ASN1Message_t *pm2 = NULL;
    status = decode_ASN1Message_message(data, data_size, &pm2);
    ASSERT_EQ(status, PEP_STATUS_OK);

    message *msg2 = ASN1Message_to_message(pm2, NULL, false, 1024);

    ASSERT_STREQ(msg2->id, "423");
    ASSERT_STREQ(msg2->shortmsg, "hello, world");
    ASSERT_STREQ(msg2->longmsg, "long message");
    ASSERT_STREQ(msg2->longmsg_formatted, "<p>long message</p>");
    ASSERT_STREQ(msg2->attachments->mime_type, "text/plain");
    ASSERT_EQ(msg2->attachments->next->value[0], 'b');
    ASSERT_NULL(msg2->attachments->next->next);
    ASSERT_EQ(msg2->sent->tm_sec, 23);
    ASSERT_EQ(msg2->recv->tm_sec, 42);
    ASSERT_STREQ(msg2->from->user_id, "23");
    ASSERT_STREQ(msg2->to->ident->user_id, "42");
    ASSERT_STREQ(msg2->to->next->ident->user_id, "23");
    ASSERT_STREQ(msg2->recv_by->user_id, "42");
    ASSERT_STREQ(msg2->cc->next->ident->user_id, "23");
    ASSERT_STREQ(msg2->bcc->next->ident->user_id, "23");
    ASSERT_STREQ(msg2->reply_to->next->ident->user_id, "23");
    ASSERT_STREQ(msg2->in_reply_to->value, "23234242");
    ASSERT_STREQ(msg2->in_reply_to->next->value, "323234242");
    ASSERT_STREQ(msg2->references->next->value, "323234242");
    ASSERT_STREQ(msg2->keywords->next->value, "else");
    ASSERT_STREQ(msg2->comments, "hello there");
    ASSERT_STREQ(msg2->opt_fields->value->key, "key");
    ASSERT_STREQ(msg2->opt_fields->next->value->value, "othervalue");
    ASSERT_STREQ(msg2->_sender_fpr, "2342234223422342");

    free_ASN1Message(pm);
    free_ASN1Message(pm2);
    free_message(msg);
    free_message(msg2);
    free(data);
}

