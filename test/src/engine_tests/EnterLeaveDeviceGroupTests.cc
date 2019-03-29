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
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_many"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_many)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_not_me"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_not_me)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_many_w_not_me"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_many_w_not_me)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_empty"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_empty)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_one"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_one)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many_w_not_me"),
                                                                      static_cast<Func>(&EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many_w_not_me)));
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_no_own() {    
    pEp_identity* alice_id = NULL;
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

    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_empty() {    
    pEp_identity* alice_id = NULL;
    PEP_STATUS status = set_up_ident_from_scratch(session,
                                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                                "ALICE", "Alice in Wonderland", &alice_id, true
                        );    

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    status = myself(session, alice_id);

    TEST_ASSERT(alice_id->me);
    TEST_ASSERT(strcmp(alice_id->fpr, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
    status = enter_device_group(session, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    status = myself(session, alice_id);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    TEST_ASSERT_MSG(alice_id->flags & PEP_idf_devicegroup, tl_ident_flags_String(alice_id->flags).c_str());
                        
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_one() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_many() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_not_me() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_one_own_single_many_w_not_me() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_empty() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_one() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many() {    
    TEST_ASSERT(true);
}

void EnterLeaveDeviceGroupTests::check_enter_device_group_many_own_many_w_not_me() {    
    TEST_ASSERT(true);
}
