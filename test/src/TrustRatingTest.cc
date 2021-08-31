// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include "mime.h"
#include "message_api.h"
#include "TestUtilities.h"



#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for TrustRatingTest
    class TrustRatingTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            // Don't clutter the global namespace
            static const char* alice_fpr; // = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
            static const char* bob_fpr; // = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";

            const char* test_suite_name;
            const char* test_name;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            TrustRatingTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~TrustRatingTest() override {
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
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
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
            string test_path;
            // Objects declared here can be used by all tests in the TrustRatingTest suite.

    };

}  // namespace

const char* TrustRatingTest::alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
const char* TrustRatingTest::bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";

static void alice_and_bob(PEP_SESSION session, pEp_identity *&alice, pEp_identity *&bob)
{
    output_stream << "\nsetting up Alice and Bob…\n";

    alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    bob = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::BOB, true, false);
    PEP_STATUS status = myself(session, alice);
    ASSERT_OK;
    status = update_identity(session, bob);
    ASSERT_OK;

    message* msg = new_message(PEP_dir_outgoing);

    output_stream << "\ndone\n";
}

TEST_F(TrustRatingTest, check_add_rating) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";

    PEP_rating sum = add_rating(PEP_rating_unreliable, PEP_rating_trusted);
    ASSERT_EQ(sum, PEP_rating_unreliable);

    sum = add_rating(PEP_rating_trusted, PEP_rating_undefined);
    ASSERT_EQ(sum, PEP_rating_undefined);
}

TEST_F(TrustRatingTest, check_rating_of_new_channel) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
 
    // rating_of_new_channel() will call update_identity()
    bob->comm_type = PEP_ct_unknown;
    free(bob->fpr);
    bob->fpr = NULL;

    PEP_rating rating;
    status = rating_of_new_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // repeat with comm_type
    rating = PEP_rating_undefined;
    status = last_rating_of_new_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // repeat without comm_type
    rating = PEP_rating_undefined;
    bob->comm_type = PEP_ct_unknown;
    status = last_rating_of_new_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");
    status = rating_of_new_channel(session, sylvia, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_have_no_key);

    // repeat
    rating = PEP_rating_undefined;
    sylvia->comm_type = PEP_ct_unknown;
    status = last_rating_of_new_channel(session, sylvia, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_have_no_key);

the_end:
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}

TEST_F(TrustRatingTest, check_rating_of_existing_channel) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    // this calls myself(session, alice) and update_identity(session, bob) (It didn't before, FWIW; does now. - KB)
    alice_and_bob(session, alice, bob);
 
    PEP_rating rating;
    status = rating_of_existing_channel(session, bob, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    // key is there and good so this should be reliable
    ASSERT_EQ(rating, PEP_rating_reliable);
    ASSERT_STREQ(bob->fpr, bob_fpr);

    // sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");
    status = update_identity(session, sylvia);
    ASSERT_EQ(status , PEP_STATUS_OK);

    status = rating_of_existing_channel(session, sylvia, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_have_no_key);

the_end:
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}

TEST_F(TrustRatingTest, check_outgoing_message_rating) {
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
 
    // sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");

    // outgoing message from Alice to Bob
    message *src = new_message(PEP_dir_outgoing);
    assert(src);
    src->from = identity_dup(alice);
    assert(src->from);
    src->to = new_identity_list(identity_dup(bob));
    assert(src->to && src->to->ident);

    PEP_rating rating;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);
 
    rating = PEP_rating_undefined;
    status = outgoing_message_rating_preview(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);

    // outgoing message from Alice to Sylvia
    free_identity(src->to->ident);
    src->to->ident = identity_dup(sylvia);
    assert(src->to->ident);

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
 
    rating = PEP_rating_undefined;
    status = outgoing_message_rating_preview(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    // outgoing message from Alice to Sylvia, and Bob CC
    src->cc = new_identity_list(identity_dup(bob));
    assert(src->cc && src->cc->ident);

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
 
    // outgoing message from Alice to Alice, and Bob CC
    free_identity(src->to->ident);
    src->to->ident = identity_dup(alice);
    assert(src->to->ident);

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);

    // outgoing message from Alice to Alice
    free_identity_list(src->cc);
    src->cc = nullptr;

    rating = PEP_rating_undefined;
    status = outgoing_message_rating(session, src, &rating);
    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_trusted_and_anonymized);

the_end:
    free_message(src);
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}

/*
    Test Cases for Trust Rating of Incoming Messages

    N.B. This text has been updated because it didn't reflect the reality of default key claims and how they work
    (see https://dev.pep.foundation/Engine/RatingsTable for the only real information we have about how this
    is supposed to work, along with https://dev.pep.foundation/Engine/TOFU).

    Dramatis personae

    Alice: the own user
    Bob: Alice frequent comm partner
    Sylvia: a new comm partner of Alice

    Note: these are now *mostly* marked with the status of whether or not they are covered in DefaultFromMailTest instead

    A) Handshake and TOFU

    1)  *Sylvia sends an unencrypted mail without key
        => unencrypted, no default key
        (COVERED IN DFMT)
    2)  *Sylvia sends an unencrypted mail with multiple keys attached and no sender_key.asc
        => unencrypted, no default key
        (COVERED IN DFMT)
    3)  *Sylvia sends an unencrypted mail with sender_key.asc filename
        => default key set, unencrypted
        (COVERED IN DFMT)
    4)  *Sylvia sends an unencrypted mail with single key attached
        => default key set, unencrypted
        (COVERED IN DFMT)

    B) Reliable Channel to Bob

    5)  *Bob sends an unencrypted mail without key
        => unencrypted
        (COVERED IN DFMT)
    6)  *Bob sends an unencrypted mail with key attached - all cases
        => key imported, default key not changed, unencrypted
        (COVERED IN DFMT)

    // NOTE: THESE DEPEND ON WHAT KIND OF PARTNER BOB IS AND WHAT KIND OF MESSAGES HE IS SENDING.
    //       CLAIMS ARE NOT AS CUT-AND-DRIED AS THIS OUTLINE MAKES THEM OUT TO BE
    //       (Only really reasonable for 2.1+))
    7)  Bob sends a 2.2+ encrypted mail, wrong claim for sender key
        => b0rken
    8) Bob sends a 2.2+ encrypted mail, correct sender key but not default key
        => unreliable
    9) Bob sends a 2.2+ encrypted mail, correct sender key and default key
        => reliable

    C) Trustwords check between Alice and Bob was successful

    10) *Bob sends an unencrypted mail without key
        => unencrypted
        (COVERED IN DFMT)
    11) *Bob sends an unencrypted mail with key attached - all cases
        => key imported, default key not changed, unencrypted
        (COVERED IN DFMT)

    // NOTE: THESE DEPEND ON WHAT KIND OF PARTNER BOB IS AND WHAT KIND OF MESSAGES HE IS SENDING.
    //       CLAIMS ARE NOT AS CUT-AND-DRIED AS THIS OUTLINE MAKES THEM OUT TO BE
    //       (Only really reasonable for 2.1+))
    12) Bob sends a 2.2 encrypted mail, wrong claim for sender key
        => b0rken
    13) Bob sends a 2.2 encrypted mail, correct sender key but not default key
        => unreliable
    14) Bob sends a 2.2 encrypted mail, correct sender key and default key
        => trusted

*/

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR) == NULL || (STR)[0] == '\0')
#endif

static bool default_key_set(PEP_SESSION session, pEp_identity *ident)
{
    assert(ident);

    PEP_STATUS status = update_identity(session, ident);
    assert(status == PEP_STATUS_OK);

    return !EMPTYSTR(ident->fpr);
}

// Let's please break this up - monolithic unit tests are hard to debug.

//    A) Handshake and TOFU
//    1)  Sylvia sends an unencrypted mail without key => unencrypted (no default key, but not tested here)
TEST_F(TrustRatingTest, check_incoming_message_rating_unknown_sender_no_key_unencrypted) {
    pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    ASSERT_NOTNULL(alice);

    message* incoming = string_to_msg("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted_NoKey.eml");
    ASSERT_NOTNULL(incoming);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    // Note, we're NOT testing the real thing here. This is kind of a problem. We want decrypt_and_verify,
    // and this is decrypt_message. But we'd have to replicate the entirety of _decrypt_message to
    // get all of the info we want here otherwise.
    PEP_STATUS decrypt_status = decrypt_message(session, incoming, &dec_msg, &keylist, &rating, &flags);
    ASSERT_NULL(dec_msg);
    ASSERT_NULL(keylist);
    ASSERT_EQ(decrypt_status, PEP_UNENCRYPTED);

    PEP_STATUS status = incoming_message_rating(session, incoming, dec_msg, keylist, nullptr, decrypt_status, &rating);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    free_message(incoming);
}

//    A) Handshake and TOFU
//    2) Sylvia sends an unencrypted mail with key attached, no claim
//        => unencrypted, no default key (Sylvia ***is a pEp user***, so we want the correct filename)
TEST_F(TrustRatingTest, check_incoming_message_rating_unknown_sender_no_key_unencrypted_key_bad_filename) {
    pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    ASSERT_NOTNULL(alice);

    message* incoming = string_to_msg("test_mails/test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted_wrong_key_filename.eml");
    ASSERT_NOTNULL(incoming);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    // Note, we're NOT testing the real thing here. This is kind of a problem. We want decrypt_and_verify,
    // and this is decrypt_message. But we'd have to replicate the entirety of _decrypt_message to
    // get all of the info we want here otherwise.
    PEP_STATUS decrypt_status = decrypt_message(session, incoming, &dec_msg, &keylist, &rating, &flags);
    ASSERT_NULL(dec_msg);
    ASSERT_NULL(keylist);
    ASSERT_EQ(decrypt_status, PEP_UNENCRYPTED);

    PEP_STATUS status = incoming_message_rating(session, incoming, dec_msg, keylist, nullptr, decrypt_status, &rating);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    free_message(incoming);
}

//    A) Handshake and TOFU
//    3)  Sylvia sends an unencrypted mail with sender key identified
//        => default key set (not checked here), unencrypted
TEST_F(TrustRatingTest, check_incoming_message_rating_unknown_sender_no_key_unencrypted_key_correct_filename) {
    pEp_identity* alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    ASSERT_NOTNULL(alice);

    message* incoming = string_to_msg("test_mails/CanonicalFrom2.2SylviaToAliceUnencrypted.eml");
    ASSERT_NOTNULL(incoming);

    message* dec_msg = NULL;
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;

    // Note, we're NOT testing the real thing here. This is kind of a problem. We want decrypt_and_verify,
    // and this is decrypt_message. But we'd have to replicate the entirety of _decrypt_message to
    // get all of the info we want here otherwise.
    PEP_STATUS decrypt_status = decrypt_message(session, incoming, &dec_msg, &keylist, &rating, &flags);
    ASSERT_NULL(dec_msg);
    ASSERT_NULL(keylist);
    ASSERT_EQ(decrypt_status, PEP_UNENCRYPTED);

    PEP_STATUS status = incoming_message_rating(session, incoming, dec_msg, keylist, nullptr, decrypt_status, &rating);
    ASSERT_OK;
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    free_message(incoming);
}

TEST_F(TrustRatingTest, check_reliable_bob_sender_signer_match) {
    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);

    string filename = "test_mails/CanonicalFrom2.2BobToAlice_2_2.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    PEP_STATUS status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);

    free_message(infile);
}

TEST_F(TrustRatingTest, check_trusted_bob_sender_signer_match) {
    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
    PEP_STATUS status = trust_personal_key(session, bob);
    ASSERT_OK;

    string filename = "test_mails/CanonicalFrom2.2BobToAlice_2_2.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_trusted);
    free_message(infile);
}

TEST_F(TrustRatingTest, check_reliable_bob_sender_signer_mismatch) {
    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);

    string filename = "test_mails/CanonicalFrom3.1BobToAlice_2_2_claim_doesnt_match_signer.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    PEP_STATUS status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_DECRYPTED);
    ASSERT_EQ(rating, PEP_rating_b0rken);
    free_message(infile);
}

TEST_F(TrustRatingTest, check_trusted_bob_sender_signer_mismatch) {
    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
    PEP_STATUS status = trust_personal_key(session, bob);
    ASSERT_OK;

    string filename = "test_mails/CanonicalFrom3.1BobToAlice_2_2_claim_doesnt_match_signer.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_DECRYPTED);
    ASSERT_EQ(rating, PEP_rating_b0rken);
    free_message(infile);
}

/*
 * FIXME: I wrote these cases to deal with the following questions
 * 15:17 <darthmama> Ah, and regarding what I just said, I guess I should clarify: there are sort of three cases for "I just received a proper message from someone with matching
 *                   signer and sender keys, but the key used wasn't this identity's default"
 * 15:17 <darthmama> 1) The key is still one with an entry in the trust DB and belongs to the identity's user
 * 15:18 <darthmama> 2) The key might have a trust DB entry, which not for this user, which should behave equivalently to:
 * 15:18 <darthmama> 3) We don't know anything about that key for Bob.
 * 15:18 <darthmama> So I'm really asking what should happen for 1
 *
 * My presumption so far is that for 1), the rating should still depend on the user trust rating for the used key (so if Bob's default key is not trusted, but the trust entry present for User Bob's
 * key IS, then all else being equal, the message signed by that key will be PEP_rating_trusted.
 * And that if it's just a reliable key, then reliable.
 *
 * 2 and 3) are pretty clearly covered by the assumption that messages encrypted to unknown or unassociated-with-the-user-keys are always unreliable, even if signed correctly.
 */

// CASE 1: Key used on the message is no longer the default, but is associated with Bob's user_id in the trust DB

// Give Bob a new default, but make sure the old one is in the trust DB so we know it's reliable
TEST_F(TrustRatingTest, check_bob_sender_key_is_bobs_and_untrusted_but_is_not_default) {
    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);

    // Set BOB2.fpr as default key
    bob = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::BOB2, true, false);
    PEP_STATUS status = update_identity(session, bob);
    ASSERT_OK;

    ASSERT_STREQ(bob->fpr, TestUtilsPreset::presets[TestUtilsPreset::BOB2].fpr);
    ASSERT_EQ(bob->comm_type, PEP_ct_pEp_unconfirmed);

    string filename = "test_mails/CanonicalFrom2.2BobToAlice_2_2.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_reliable);
    free_message(infile);
}

// Give Bob a new default, but make sure the old one is in the trust DB and trusted so we know it's reliable (and don't trust
// the new one so we see the difference) - N.B. This one fails, Volker needs figure out/spec what is wanted (see above)
TEST_F(TrustRatingTest, check_bob_sender_key_is_bobs_and_trusted_but_is_not_default) {
    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);
    PEP_STATUS status = trust_personal_key(session, bob);
    ASSERT_OK;

    // Set BOB2.fpr as default key
    bob = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::BOB2, true, false);
    status = update_identity(session, bob);
    ASSERT_STREQ(bob->fpr, TestUtilsPreset::presets[TestUtilsPreset::BOB2].fpr);
    ASSERT_EQ(bob->comm_type, PEP_ct_pEp_unconfirmed);

    string filename = "test_mails/CanonicalFrom2.2BobToAlice_2_2.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // The mail was sent with the trusted sender, so this should be true. If it's false, incoming message rating is broken.
    // This is a valid, verified key for this user. However, Volker may want ratings bound much more closely to identities than before,
    // so this is an fdik FIXME.
    ASSERT_EQ(rating, PEP_rating_trusted);
    free_message(infile);
}

// CASE 2: Key used for the message is in the trust DB for some user, but that user is not BOB.

// Give Bob a new default, but make sure the old one is in the trust DB and trusted so we know it's reliable (and don't trust
// the new one so we see the difference)
TEST_F(TrustRatingTest, check_reliable_bob_sender_key_is_someone_elses_in_db) {
    pEp_identity *alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    PEP_STATUS status = myself(session, alice);
    ASSERT_OK;

    // This will ONLY import the key and generate an identity which we'll toss. This WON'T record this as Bob's key in the DB.
    pEp_identity* bob = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::BOB); // Signing key imported
    // Trash old Bob, make way for new Bob
    free_identity(bob);
    bob = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::BOB2, true, false);
    // Now, make Carol pay for Bob's crimes! I mean, um, let's make Carol and give her Bob's key as her default.
    pEp_identity* carol = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::CAROL); // Doesn't matter if Carol's key was imported, not really "hers"
    free(carol->fpr);
    carol->fpr = strdup(TestUtilsPreset::presets[TestUtilsPreset::BOB].fpr);
    status = set_identity(session, carol);
    ASSERT_OK;
    status = update_identity(session, carol);
    ASSERT_OK;
    ASSERT_STREQ(carol->fpr, TestUtilsPreset::presets[TestUtilsPreset::BOB].fpr);

    status = update_identity(session, bob);
    ASSERT_OK;
    ASSERT_STREQ(bob->fpr, TestUtilsPreset::presets[TestUtilsPreset::BOB2].fpr);

    ASSERT_STRNE(bob->fpr, carol->fpr);

    // Ok, so now Carol own's "Bob's" key, but Alice is about to receive a message from Bob encrypted with "Carol's" key

    string filename = "test_mails/CanonicalFrom2.2BobToAlice_2_2.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // The mail was sent with the trusted sender, so this should be true. If it's false, incoming message rating is broken.
    // This is a valid, verified key for this user. However, Volker may want ratings bound much more closely to identities than before,
    // so this is an fdik FIXME.
    ASSERT_EQ(rating, PEP_rating_unreliable);
    free_message(infile);
}

// CASE 3: We have a default key for BOB, but it's not on the message, and the sender key is in keys.db, but NOT in the trust DB.
// Give Bob a new default, but make sure the old one is in the trust DB and trusted so we know it's reliable (and don't trust
// the new one so we see the difference)
TEST_F(TrustRatingTest, check_reliable_bob_sender_key_not_bobs_and_not_in_trust_db) {
    pEp_identity *alice = TestUtilsPreset::generateAndSetPrivateIdentity(session, TestUtilsPreset::ALICE);
    PEP_STATUS status = myself(session, alice);
    ASSERT_OK;

    // This will ONLY import the key and generate an identity which we'll toss. This WON'T record this as Bob's key in the DB.
    pEp_identity* bob = TestUtilsPreset::generateOnlyPartnerIdentity(session, TestUtilsPreset::BOB); // Message Signing key imported
    // Trash old Bob, make way for new Bob
    free_identity(bob);
    bob = TestUtilsPreset::generateAndSetpEpPartnerIdentity(session, TestUtilsPreset::BOB2, true, false);

    // Now, get message from Bob with the wrong key!
    string filename = "test_mails/CanonicalFrom2.2BobToAlice_2_2.eml";
    message* infile = NULL;
    PEP_rating rating = PEP_rating_undefined;
    status = vanilla_read_file_and_decrypt_with_rating(session, &infile,
                                                                  filename.c_str(), &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);

    // The mail was sent with the trusted sender, so this should be true. If it's false, incoming message rating is broken.
    // This is a valid, verified key for this user. However, Volker may want ratings bound much more closely to identities than before,
    // so this is an fdik FIXME.
    ASSERT_EQ(rating, PEP_rating_unreliable);
    free_message(infile);
}


TEST_F(TrustRatingTest, check_incoming_message_rating) {
    // TEST FIX: This test won't work until run though decrypt_message, Volker!
    output_stream << "\n*** " << test_suite_name << ": " << test_name << " ***\n";
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *alice;
    pEp_identity *bob;
    alice_and_bob(session, alice, bob);

    // Sylvia is unknown 
    pEp_identity *sylvia = new_identity("sylvia@test.pep", NULL, NULL, "Sylvia");

    // incoming message from Sylvia to Alice
    message *src = new_message(PEP_dir_incoming);
    assert(src);
    src->from = identity_dup(sylvia);
    assert(src->from);
    src->to = new_identity_list(identity_dup(alice));
    assert(src->to && src->to->ident);
    src->shortmsg = strdup("pEp");
    assert(src->shortmsg);

    PEP_rating rating = PEP_rating_undefined;


    // 1)  Sylvia sends an unencrypted mail without key

    message* dst = NULL;
    stringlist_t* keylist = NULL;
    PEP_decrypt_flags_t flags = 0;

    status = decrypt_message(session, src, &dst, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(dst);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    status = incoming_message_rating(session, src, nullptr, keylist, nullptr,
            PEP_UNENCRYPTED, &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
    ASSERT_EQ(default_key_set(session, sylvia), false);

    // 2)  N.B. This test case makes no sense - we don't have a "no claim" for unencrypted messages except that
    //          there might be multiple keys. So I presume you're just testing incoming_message_rating on some
    //          message that will never occur here.
    //     Sylvia sends an unencrypted mail with key attached, no claim
    //     => unencrypted, no default key
    
    std::string sylvias_key = slurp("test_keys/pub/sylvia-0x585A6780_pub.asc");
    src->attachments = new_bloblist(strdup(sylvias_key.c_str()), sylvias_key.size(),
            "application/pgp-keys", "sylvia-pub.asc");
    assert(src->attachments && src->attachments->value);

    status = incoming_message_rating(session, src, nullptr, nullptr, nullptr,
            PEP_UNENCRYPTED, &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
    ASSERT_EQ(default_key_set(session, sylvia), false);

    // 3)  Sylvia sends an unencrypted mail with sender key identified
    //     => default key set, unencrypted
    
    ASSERT_TRUE(slurp_and_import_key(session, "test_keys/pub/sylvia-0x585A6780_pub.asc"));

    stringlist_t *known_keys = new_stringlist("0C0F053EED87058C7330A11F10B89D31585A6780");
    assert(known_keys);

    // There's only a "claim" if you decrypt it first.
    free_stringlist(keylist);
    keylist = NULL;
    flags = 0;

    status = decrypt_message(session, src, &dst, &keylist, &rating, &flags);
    ASSERT_EQ(status, PEP_UNENCRYPTED);
    ASSERT_NULL(dst);
    ASSERT_EQ(rating, PEP_rating_unencrypted);

    // I don't see what "known keys" has to do with anything here. It's an unencrypted message,
    // and the known keys will come from the DB. But OK.
    status = incoming_message_rating(session, src, nullptr, known_keys, nullptr,
            PEP_UNENCRYPTED, &rating);
    ASSERT_EQ(status, PEP_STATUS_OK);
    ASSERT_EQ(rating, PEP_rating_unencrypted);
    ASSERT_EQ(default_key_set(session, sylvia), true);
    
the_end:
    free_stringlist(known_keys);
    free_message(src);
    free_identity(alice);
    free_identity(bob);
    free_identity(sylvia);
}
