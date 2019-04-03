// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>

#include "pEpEngine.h"

#include "test_util.h"
#include "sync_api.h"
#include <cpptest.h>
#include "EngineTestIndividualSuite.h"
#include "EnterLeaveDeviceGroupTests.h"

using namespace std;

EnterLeaveDeviceGroupTests::EnterLeaveDeviceGroupTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_no_own"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_no_own)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_empty"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_empty)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_one"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_one)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_reversed_by_many"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_reversed_by_many)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_not_me"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_not_me)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_many_w_not_me"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_many_w_not_me)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_empty"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_empty)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_add_explicit"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_add_explicit)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_one"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_one)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many_w_not_me"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many_w_not_me)));
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_no_own() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, false
                        );
                        
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = enter_device_group(session, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = update_identity(session, alice_id);
    TEST_ASSERT(!(alice_id->flags & PEP_idf_devicegroup));
    
    free_identity(alice_id);
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_empty() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(alice_id->me);
    TEST_ASSERT(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                "BOB", "Bob is not Alice", &bob_id, false
                        );    
    status = update_identity(session, bob_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = enter_device_group(session, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = update_identity(session, bob_id);
    TEST_ASSERT_MSG(!(bob_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id->flags).c_str());

    free_identity(alice_id);
    free_identity(bob_id);
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_one() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = myself(session, alice_id);

    TEST_ASSERT(alice_id->me);
    TEST_ASSERT(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());
                        
    free_identity(alice_id);                        
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_reversed_by_many() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = myself(session, alice_id);

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Bob is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    // First, add Alice to device group and ensure the other two are not added
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());
    
    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id2->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id3->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id3->flags).c_str());

    // Note: this is a shortcut to omit alice_id from ident list
    ids_to_group->ident = alice_id2;
    
    identity_list_add(ids_to_group, alice_id3);
    
    // Add 2 and 3 to device group (hopefully removing alice_id)
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Is alice_id in? (shouldn't be)
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id->flags).c_str());
    
    // are 2 and 3 in? (should be)
    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());
                        
    free_identity_list(ids_to_group);
    free_identity(alice_id);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_not_me() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = myself(session, alice_id);

    TEST_ASSERT(alice_id->me);
    TEST_ASSERT(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                "BOB", "Bob is not Alice", &bob_id, false
                        );    

    ids_to_group->ident = bob_id;
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status != PEP_STATUS_OK, tl_status_string(status));
    status = update_identity(session, bob_id);
    TEST_ASSERT_MSG(!(bob_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id);    
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());
                        
    free_identity(alice_id);                        
    free_identity_list(ids_to_group);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_many_w_not_me() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = myself(session, alice_id);

    TEST_ASSERT(alice_id->me);
    TEST_ASSERT(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    identity_list* ids_to_group = new_identity_list(alice_id);
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                "BOB", "Bob is not Alice", &bob_id, false
                        );    

    ids_to_group->ident = alice_id2;
    identity_list_add(ids_to_group, bob_id);
    identity_list_add(ids_to_group, alice_id3);
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status != PEP_STATUS_OK, tl_status_string(status));
    status = update_identity(session, bob_id);
    TEST_ASSERT_MSG(!(bob_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id);    
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id2->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id3->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id3->flags).c_str());
                        
    free_identity(alice_id);                        
    free_identity_list(ids_to_group);
}
void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_add_explicit() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    identity_list_add(ids_to_group, alice_id3);
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    status = myself(session, alice_id);    
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());
                        
    free_identity_list(ids_to_group);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_empty() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = enter_device_group(session, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());
                        
    free_identity(alice_id);         
    free_identity(alice_id2);
    free_identity(alice_id3);               
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_one() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    identity_list* ids_to_group = new_identity_list(alice_id2);
    identity_list_add(ids_to_group, alice_id3);
    
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());

    identity_list* tmp = ids_to_group->next;
    ids_to_group->next = NULL;
    tmp->ident = NULL;
    free_identity_list(tmp);

    ids_to_group->ident = alice_id;

    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id2->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id3->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id3->flags).c_str());
                        
    free_identity_list(ids_to_group);         
    free_identity(alice_id2);
    free_identity(alice_id3);               
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    pEp_identity* alice_id4 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_4@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Dave is Alice", &alice_id4, true
                        );    

    pEp_identity* alice_id5 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_5@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Eustace is Alice", &alice_id5, true
                        );    

    pEp_identity* alice_id6 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_6@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Francesca is Alice", &alice_id6, true
                        );    


    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id4);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id5);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id6);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    identity_list_add(ids_to_group, alice_id3);
    
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());

    ids_to_group->ident = alice_id4;
    ids_to_group->next->ident = alice_id5;
    ids_to_group->next->next->ident = alice_id6;

    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id2->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id3->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id3->flags).c_str());

    status = myself(session, alice_id4);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id4->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id4->flags).c_str());

    status = myself(session, alice_id5);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id5->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id5->flags).c_str());

    status = myself(session, alice_id6);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id6->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id6->flags).c_str());
                        
    free_identity_list(ids_to_group);         
    free_identity(alice_id);
    free_identity(alice_id2);
    free_identity(alice_id3);               
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many_w_not_me() {    
    pEp_identity* alice_id = NULL;
    TEST_ASSERT(slurp_and_import_key(session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"));    
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    pEp_identity* alice_id2 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_2@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Barbara is Alice", &alice_id2, true
                        );    

    pEp_identity* alice_id3 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_3@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Carol is Alice", &alice_id3, true
                        );    

    pEp_identity* alice_id4 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_4@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Dave is Alice", &alice_id4, true
                        );    

    pEp_identity* alice_id5 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_5@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Eustace is Alice", &alice_id5, true
                        );    

    pEp_identity* alice_id6 = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice_6@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Francesca is Alice", &alice_id6, true
                        );    

    pEp_identity* bob_id = NULL;
    status = set_up_ident_from_scratch(session,
                                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                                "pep.test.bob@pep-project.org", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39", 
                                "BOB", "Bob is not Alice", &bob_id, false
                        );    

    status = update_identity(session, bob_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id4);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id5);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    status = myself(session, alice_id6);
    TEST_ASSERT(status == PEP_STATUS_OK);    

    identity_list* ids_to_group = new_identity_list(alice_id);
    identity_list_add(ids_to_group, alice_id2);
    identity_list_add(ids_to_group, alice_id3);
    
    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());

    ids_to_group->ident = alice_id4;
    ids_to_group->next->ident = alice_id5;
    ids_to_group->next->next->ident = alice_id6;
    ids_to_group->next->next->next = new_identity_list(bob_id);

    status = enter_device_group(session, ids_to_group);
    TEST_ASSERT_MSG(status == PEP_ILLEGAL_VALUE, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());

    status = myself(session, alice_id2);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id2->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id2->flags).c_str());

    status = myself(session, alice_id3);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id3->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id3->flags).c_str());

    status = myself(session, alice_id4);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id4->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id4->flags).c_str());

    status = myself(session, alice_id5);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id5->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id5->flags).c_str());

    status = myself(session, alice_id6);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(alice_id6->flags & PEP_idf_devicegroup), tl_ident_flags_String(alice_id6->flags).c_str());
    
    status = update_identity(session, bob_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(!(bob_id->flags & PEP_idf_devicegroup), tl_ident_flags_String(bob_id->flags).c_str());
    
    free_identity_list(ids_to_group);         
    free_identity(alice_id);
    free_identity(alice_id2);
    free_identity(alice_id3);               
}
