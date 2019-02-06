// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "UserIdCollisionTests.h"

using namespace std;

UserIdCollisionTests::UserIdCollisionTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::simple_tofu_collision"),
                                                                      static_cast<Func>(&UserIdCollisionTests::simple_tofu_collision)));                                                                  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::simple_tofu_collision_different_usernames"),
                                                                      static_cast<Func>(&UserIdCollisionTests::simple_tofu_collision_different_usernames)));                                                                                                                                        
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::tofu_collision_two_tofus"),
                                                                      static_cast<Func>(&UserIdCollisionTests::tofu_collision_two_tofus)));                                                                                                                                                                                                              
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::tofu_collision_two_tofus_diff_usernames"),
                                                                      static_cast<Func>(&UserIdCollisionTests::tofu_collision_two_tofus_diff_usernames)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::real_followed_by_explicit_tofu"),
                                                                      static_cast<Func>(&UserIdCollisionTests::real_followed_by_explicit_tofu)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::merge_records_normal"),
                                                                      static_cast<Func>(&UserIdCollisionTests::merge_records_normal)));                                                                  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::merge_records_set"),
                                                                      static_cast<Func>(&UserIdCollisionTests::merge_records_set)));                                                                  
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("UserIdCollisionTests::merge_records_set_2"),
                                                                      static_cast<Func>(&UserIdCollisionTests::merge_records_set_2)));                                                                                                                                        
}

void UserIdCollisionTests::setup() {
    EngineTestIndividualSuite::setup();
    user_alice = new_identity(alice_email, alice_keyid, PEP_OWN_USERID, "Alice from Mel's Diner");
    slurp_and_import_key(session, alice_keyfile);    
    
    real_alex = new_identity(alex_email, alex_keyid, "AlexID", "Alexander the Mediocre");
    
    tofu_alex = new_identity(alex_email, alex_keyid, NULL, NULL);

    real_alex_0 = new_identity(alex_email, alex_keyid, "Alex0", "Alexander the Mediocre");
    
    tofu_alex_0 = new_identity(alex_email, alex_keyid, NULL, NULL);
    
    real_alex_1 = new_identity(alex1_email, alex_keyid, "Alex1", NULL);
    
    tofu_alex_1 = new_identity(alex1_email, alex1_keyid, NULL, NULL);

    real_alex_2 = new_identity(alex2_email, alex1_keyid, "Alex2", NULL);

    tofu_alex_2 = new_identity(alex2_email, alex2_keyid, NULL, NULL);

    real_alex_3 = new_identity(alex3_email, alex2_keyid, "Alex3", NULL);

    tofu_alex_3 = new_identity(alex3_email, alex3_keyid, NULL, NULL);

    real_alex_4 = new_identity(alex4_email, alex3_keyid, "Alex4", NULL);

    tofu_alex_4 = new_identity(alex4_email, alex4_keyid, NULL, NULL);

    real_alex_5 = new_identity(alex5_email, alex4_keyid, "Alex5", NULL);

    tofu_alex_5 = new_identity(alex5_email, alex5_keyid, NULL, NULL);

    real_alex_6a = new_identity(alex6_email, alex5_keyid, "Alex6", NULL);

    tofu_alex_6a = new_identity(alex6_email, alex6a_keyid, NULL, NULL);

    real_alex_6b = new_identity(alex6_email, alex6a_keyid, "Alex6", NULL);

    tofu_alex_6b = new_identity(alex6_email, alex6b_keyid, NULL, NULL);

    real_alex_6c = new_identity(alex6_email, alex6b_keyid, "Alex6", NULL);

    tofu_alex_6c = new_identity(alex6_email, alex6c_keyid, NULL, NULL);

    real_alex_6d = new_identity(alex6_email, alex6c_keyid, "Alex6", NULL);

    tofu_alex_6d = new_identity(alex6_email, alex6d_keyid, NULL, NULL);
}

void UserIdCollisionTests::tear_down() {
    free_identity(real_alex);
    free_identity(real_alex_0);
    free_identity(real_alex_1);
    free_identity(real_alex_2);
    free_identity(real_alex_3);
    free_identity(real_alex_4);
    free_identity(real_alex_5);
    free_identity(real_alex_6a);
    free_identity(real_alex_6b);
    free_identity(real_alex_6c);
    free_identity(real_alex_6d);
    free_identity(tofu_alex);
    free_identity(tofu_alex_0);
    free_identity(tofu_alex_1);
    free_identity(tofu_alex_2);
    free_identity(tofu_alex_3);
    free_identity(tofu_alex_4);
    free_identity(tofu_alex_5);
    free_identity(tofu_alex_6a);
    free_identity(tofu_alex_6b);
    free_identity(tofu_alex_6c);
    free_identity(tofu_alex_6d);
    EngineTestIndividualSuite::tear_down();    
}

void UserIdCollisionTests::simple_tofu_collision() {
    slurp_and_import_key(session,alex_keyfile);
    tofu_alex->username = strdup("Alexander the Mediocre");
    PEP_STATUS status = update_identity(session, tofu_alex);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex->fpr, alex_keyid) == 0, tofu_alex->fpr);
    string tofu_id = string("TOFU_") + alex_email;
    TEST_ASSERT_MSG(strcmp(tofu_alex->user_id, tofu_id.c_str()) == 0, tofu_alex->user_id);    
    status = update_identity(session, real_alex);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(real_alex->fpr, alex_keyid) == 0, real_alex->fpr);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex, &tofu_still_exists);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(!tofu_still_exists);    
}

void UserIdCollisionTests::simple_tofu_collision_different_usernames() {
    slurp_and_import_key(session,alex_keyfile);
    tofu_alex->username = strdup("Alexander Hamilton");
    PEP_STATUS status = update_identity(session, tofu_alex);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex->fpr, alex_keyid) == 0, tofu_alex->fpr);
    string tofu_id = string("TOFU_") + alex_email;
    TEST_ASSERT_MSG(strcmp(tofu_alex->user_id, tofu_id.c_str()) == 0, tofu_alex->user_id);    
    status = update_identity(session, real_alex);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(real_alex->fpr, alex_keyid) == 0, real_alex->fpr);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex, &tofu_still_exists);
    TEST_ASSERT(status == PEP_STATUS_OK);
    // SHOULD still exist, because we don't replace when usernames differ
    TEST_ASSERT(tofu_still_exists);    
}

void UserIdCollisionTests::tofu_collision_two_tofus() {
    slurp_and_import_key(session,alex6a_keyfile);
    
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6b->username = strdup("Alexander Hamilton");

    tofu_alex_6a->lang[0] = 'j';
    tofu_alex_6a->lang[1] = 'p';
    
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex_6a->fpr, alex6a_keyid) == 0, tofu_alex_6a->fpr);
    string tofu_id = string("TOFU_") + alex6_email;
    TEST_ASSERT_MSG(strcmp(tofu_alex_6a->user_id, tofu_id.c_str()) == 0, tofu_alex_6a->user_id);    

    // Ok, NOW we put in an explicit TOFU
    tofu_alex_6b->user_id = strdup(tofu_id.c_str());
    status = update_identity(session, tofu_alex_6b);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex_6b->fpr, alex6a_keyid) == 0, tofu_alex_6b->fpr);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex_6a, &tofu_still_exists);
    TEST_ASSERT(status == PEP_STATUS_OK);
    // SHOULD still exist, because we don't replace when usernames differ
    TEST_ASSERT(tofu_still_exists);    
    TEST_ASSERT(tofu_alex_6b->lang[0] == 'j');
    TEST_ASSERT(tofu_alex_6b->lang[1] == 'p');    
}

void UserIdCollisionTests::tofu_collision_two_tofus_diff_usernames() {
    slurp_and_import_key(session,alex6a_keyfile);
    
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6b->username = strdup("Alexander the Not-Cool-At-All");

    tofu_alex_6a->lang[0] = 'j';
    tofu_alex_6a->lang[1] = 'p';
    
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex_6a->fpr, alex6a_keyid) == 0, tofu_alex_6a->fpr);
    string tofu_id = string("TOFU_") + alex6_email;
    TEST_ASSERT_MSG(strcmp(tofu_alex_6a->user_id, tofu_id.c_str()) == 0, tofu_alex_6a->user_id);    

    // Ok, NOW we put in an explicit TOFU
    tofu_alex_6b->user_id = strdup(tofu_id.c_str());
    status = update_identity(session, tofu_alex_6b);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex_6b->fpr, alex6a_keyid) == 0, tofu_alex_6b->fpr);
    bool tofu_still_exists = false;
    status = exists_person(session, tofu_alex_6a, &tofu_still_exists);
    TEST_ASSERT(status == PEP_STATUS_OK);
    // SHOULD still exist, because we don't replace when usernames differ
    TEST_ASSERT(tofu_still_exists);    
    TEST_ASSERT(tofu_alex_6b->lang[0] == 'j');
    TEST_ASSERT(tofu_alex_6b->lang[1] == 'p');    
    TEST_ASSERT(strcmp(tofu_alex_6b->username,"Alexander the Not-Cool-At-All") == 0);    
}

void UserIdCollisionTests::real_followed_by_explicit_tofu() {
    slurp_and_import_key(session,alex_keyfile);
    real_alex->username = strdup("Alexander the Mediocre");
    PEP_STATUS status = update_identity(session, real_alex);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(real_alex->fpr, alex_keyid) == 0, real_alex->fpr);
    string tofu_id = string("TOFU_") + alex_email;
    tofu_alex->username = strdup(real_alex->username);
    tofu_alex->user_id = strdup(tofu_id.c_str());
    status = update_identity(session, tofu_alex);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(strcmp(tofu_alex->user_id, "AlexID") == 0, tofu_alex->user_id);
    bool tofu_still_exists = false;
    free(tofu_alex->user_id);
    tofu_alex->user_id = strdup(tofu_id.c_str());    
    status = exists_person(session, tofu_alex, &tofu_still_exists);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(!tofu_still_exists);    
}

void UserIdCollisionTests::merge_records_normal() {
    // Tofu 6a has lots of stuff.
    slurp_and_import_key(session,alex6a_keyfile);    
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6a->lang[0] = 'e';
    tofu_alex_6a->lang[1] = 's';
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6c_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6c_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP;    
    status = set_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6d_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6d_keyid);
    tofu_alex_6a->comm_type = PEP_ct_pEp_unconfirmed; // ???
    status = set_identity(session, tofu_alex_6a);
    real_alex_6a->username = strdup(tofu_alex_6a->username);
    status = update_identity(session, real_alex_6a);                        
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(real_alex_6a->lang[0] = 'e');
    TEST_ASSERT_MSG(real_alex_6a->comm_type == PEP_ct_pEp_unconfirmed, tl_ct_string(real_alex_6a->comm_type));
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6c_keyid);
    status = get_trust(session, real_alex_6a);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT_MSG(real_alex_6a->comm_type == PEP_ct_OpenPGP, tl_ct_string(real_alex_6a->comm_type));    
}

void UserIdCollisionTests::merge_records_set() {
    // Tofu 6a has lots of stuff.
    slurp_and_import_key(session,alex6a_keyfile);    
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6a->lang[0] = 'e';
    tofu_alex_6a->lang[1] = 's';
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6b_keyfile);        
    slurp_and_import_key(session,alex6c_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6c_keyid);
    tofu_alex_6a->comm_type = PEP_ct_pEp_unconfirmed;    
    status = set_identity(session, tofu_alex_6a);
    status = set_as_pep_user(session, tofu_alex_6a);     
    slurp_and_import_key(session,alex6d_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6d_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP;
    status = set_identity(session, tofu_alex_6a);    
    real_alex_6a->username = strdup(tofu_alex_6a->username);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = set_person(session, real_alex_6a, true); // NOT identit
    TEST_ASSERT(status == PEP_STATUS_OK);   
    status = update_identity(session, real_alex_6a);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(real_alex_6a->lang[0] = 'e');
    TEST_ASSERT_MSG(real_alex_6a->comm_type == PEP_ct_pEp, tl_ct_string(real_alex_6a->comm_type));    
    bool pEp_peep = false;
    status = is_pep_user(session, real_alex_6a, &pEp_peep);
    TEST_ASSERT(pEp_peep);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6c_keyid);
    status = get_trust(session, real_alex_6a);
    TEST_ASSERT(real_alex_6a->comm_type == PEP_ct_pEp_unconfirmed);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = get_trust(session, real_alex_6a);
    TEST_ASSERT(real_alex_6a->comm_type == PEP_ct_pEp);    
}

void UserIdCollisionTests::merge_records_set_2() {
    // Tofu 6a has lots of stuff.
    slurp_and_import_key(session,alex6a_keyfile);    
    tofu_alex_6a->username = strdup("Alexander Hamilton");
    tofu_alex_6a->lang[0] = 'e';
    tofu_alex_6a->lang[1] = 's';
    PEP_STATUS status = update_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6b_keyfile);        
    slurp_and_import_key(session,alex6c_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6c_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP_unconfirmed;    
    status = set_identity(session, tofu_alex_6a);
    slurp_and_import_key(session,alex6d_keyfile);
    free(tofu_alex_6a->fpr);
    tofu_alex_6a->fpr = strdup(alex6d_keyid);
    tofu_alex_6a->comm_type = PEP_ct_OpenPGP;
    status = set_identity(session, tofu_alex_6a);    
    real_alex_6a->username = strdup(tofu_alex_6a->username);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = set_person(session, real_alex_6a, true); // NOT identity   
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = set_as_pep_user(session, real_alex_6a);     
    TEST_ASSERT(status == PEP_STATUS_OK);    
    status = update_identity(session, real_alex_6a);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(real_alex_6a->lang[0] = 'e');
    TEST_ASSERT_MSG(real_alex_6a->comm_type == PEP_ct_pEp, tl_ct_string(real_alex_6a->comm_type));    
    bool pEp_peep = false;
    status = is_pep_user(session, real_alex_6a, &pEp_peep);
    TEST_ASSERT(pEp_peep);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6c_keyid);
    status = get_trust(session, real_alex_6a);
    TEST_ASSERT(real_alex_6a->comm_type == PEP_ct_pEp_unconfirmed);
    free(real_alex_6a->fpr);
    real_alex_6a->fpr = strdup(alex6d_keyid);
    status = get_trust(session, real_alex_6a);
    TEST_ASSERT(real_alex_6a->comm_type == PEP_ct_pEp);    
}
