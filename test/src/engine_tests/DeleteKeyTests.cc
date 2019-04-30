// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cpptest.h>

#include "pEpEngine.h"
#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "DeleteKeyTests.h"

using namespace std;

const string DeleteKeyTests::alice_user_id = PEP_OWN_USERID;
const string DeleteKeyTests::bob_user_id = "BobId";    
const string DeleteKeyTests::carol_user_id = "carolId";
const string DeleteKeyTests::dave_user_id = "DaveId";
const string DeleteKeyTests::erin_user_id = "ErinErinErin";
const string DeleteKeyTests::fenris_user_id = "BadWolf";


DeleteKeyTests::DeleteKeyTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeleteKeyTests::check_delete_single_pubkey"),
                                                                      static_cast<Func>(&DeleteKeyTests::check_delete_single_pubkey)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeleteKeyTests::check_delete_pub_priv_keypair"),
                                                                      static_cast<Func>(&DeleteKeyTests::check_delete_pub_priv_keypair)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeleteKeyTests::check_delete_multiple_keys"),
                                                                      static_cast<Func>(&DeleteKeyTests::check_delete_multiple_keys)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeleteKeyTests::check_delete_all_keys"),
                                                                      static_cast<Func>(&DeleteKeyTests::check_delete_all_keys)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeleteKeyTests::check_delete_key_not_found"),
                                                                      static_cast<Func>(&DeleteKeyTests::check_delete_key_not_found)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeleteKeyTests::check_delete_empty_keyring"),
                                                                      static_cast<Func>(&DeleteKeyTests::check_delete_empty_keyring)));
}

void DeleteKeyTests::import_test_keys() {
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    assert(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", alice_fpr, 
                alice_user_id.c_str(), "Alice in Wonderland", NULL, true
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                "pep.test.bob@pep-project.org", NULL, bob_user_id.c_str(), "Bob's Burgers",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);
            
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-carol-0x42A85A42_pub.asc",
                "pep-test-carol@pep-project.org", NULL, carol_user_id.c_str(), "Carol Burnett",
                NULL, false
            );
    assert(status == PEP_STATUS_OK);
    
    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-dave-0xBB5BCCF6_pub.asc",
                "pep-test-dave@pep-project.org", NULL, dave_user_id.c_str(), 
                "David Hasselhoff (Germans Love Me)", NULL, false
            );
    assert(status == PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-erin-0x9F8D7CBA_pub.asc",
                "pep-test-erin@pep-project.org", NULL, erin_user_id.c_str(), 
                "Éirinn go Brách", NULL, false
            );
    assert(status == PEP_STATUS_OK);

    status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.fenris-0x4F3D2900_pub.asc",
                "pep.test.fenris@thisstilldoesntwork.lu", NULL, fenris_user_id.c_str(), 
                "Fenris Leto Hawke", NULL, false
            );
    assert(status == PEP_STATUS_OK);
}

void DeleteKeyTests::check_delete_single_pubkey() {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, fenris_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, fenris_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;
    
    // Great, now delete it.
    status = delete_keypair(session, fenris_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    
    // Is it gone?
    status = find_keys(session, fenris_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    
    
    // Yay.    
}

void DeleteKeyTests::check_delete_pub_priv_keypair() {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, alice_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;
    
    // Great, now delete it.
    status = delete_keypair(session, alice_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    
    // Is it gone?
    status = find_keys(session, alice_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    
    
    // Yay.    
}

void DeleteKeyTests::check_delete_multiple_keys() {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Are they there?
    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, alice_fpr) == 0, keylist->value);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, dave_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, dave_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, fenris_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, fenris_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;
    
    // Great, now delete it.
    status = delete_keypair(session, alice_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, dave_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, fenris_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    // Is it gone?
    status = find_keys(session, alice_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, dave_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, fenris_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    
    
    // Yay. Make sure everyone else is still there.
    status = find_keys(session, bob_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, bob_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, carol_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, carol_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, erin_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, erin_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;
}

void DeleteKeyTests::check_delete_all_keys() {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Are they there?
    PEP_STATUS status = find_keys(session, alice_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, alice_fpr) == 0, keylist->value);
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, bob_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, bob_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, carol_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, carol_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, dave_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, dave_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, erin_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, erin_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;

    status = find_keys(session, fenris_fpr, &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist && keylist->value);    
    TEST_ASSERT_MSG(strcmp(keylist->value, fenris_fpr) == 0, "Wrong key found?!?!");
    free_stringlist(keylist);
    keylist = NULL;
    
    // Great, now delete it.
    status = delete_keypair(session, alice_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, bob_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, carol_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, dave_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, erin_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = delete_keypair(session, fenris_fpr);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    // Is it gone?
    status = find_keys(session, alice_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, bob_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, carol_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, dave_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, erin_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    

    status = find_keys(session, fenris_fpr, &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    
    
    // Yay. 
}

void DeleteKeyTests::check_delete_key_not_found() {
    import_test_keys();
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(!keylist);    
    
    // Great, now delete it.
    status = delete_keypair(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D");
    TEST_ASSERT(status == PEP_KEY_NOT_FOUND);    
    
    // Is it still gone?
    status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    
    
    // Yay.        
}

void DeleteKeyTests::check_delete_empty_keyring() {
    stringlist_t* keylist = NULL;

    // Is it there?
    PEP_STATUS status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(!keylist);    
    
    // Great, now delete it.
    status = delete_keypair(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D");
    TEST_ASSERT(status == PEP_KEY_NOT_FOUND);    
    
    // Is it still gone?
    status = find_keys(session, "74D79B4496E289BD8A71B70BA8E2C4530019697D", &keylist);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);    
    
    // Yay.            
}
