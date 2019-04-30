// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "OwnKeysRetrieveTests.h"

using namespace std;

OwnKeysRetrieveTests::OwnKeysRetrieveTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_single_private"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_single_private)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_single_private_single_pub"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_single_private_single_pub)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_multiple_private"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_multiple_private)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_multiple_private_and_pub"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_multiple_private_and_pub)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_multi_pub_only"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_multi_pub_only)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_no_own"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_no_own)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_multi_idents_one_key"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_multi_idents_one_key)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("OwnKeysRetrieveTests::check_own_keys_retrieve_multi_idents_one_priv_key_multi_pub"),
                                                                      static_cast<Func>(&OwnKeysRetrieveTests::check_own_keys_retrieve_multi_idents_one_priv_key_multi_pub)));
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_single_private() {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;
    
    status = _own_keys_retrieve(session, &keylist, 0, true);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(keylist);
    TEST_ASSERT(keylist->value);
    TEST_ASSERT(!keylist->next);

    TEST_ASSERT(strcmp(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_single_private_single_pub() {
    // Set up an own idea that only has a public key
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc",
                "pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, "Bob's Burgers",
                NULL, false
            );
    TEST_ASSERT(status == PEP_STATUS_OK);

    // Make it an own identity in the DB
    pEp_identity* me_bob = new_identity("pep.test.bob@pep-project.org", NULL, PEP_OWN_USERID, NULL);
    status = update_identity(session, me_bob);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(me_bob->fpr, "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39") == 0);
    status = trust_personal_key(session, me_bob);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    me_bob->me = true;
    status = set_identity(session, me_bob);
    free_identity(me_bob);
    me_bob = NULL;
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc",
                "pep.test.alice@pep-project.org", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97", 
                PEP_OWN_USERID, "Alice in Wonderland", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;
    
    status = _own_keys_retrieve(session, &keylist, 0, true);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(keylist);
    TEST_ASSERT(keylist->value);
    TEST_ASSERT(!keylist->next);

    TEST_ASSERT(strcmp(keylist->value, "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97") == 0);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_multiple_private() {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB", 
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander1-0x541260F6_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander1-0x541260F6_priv.asc",
                "pep.test.xander@pep-project.org", "59AF4C51492283522F6904531C09730A541260F6", 
                PEP_OWN_USERID, "Xander2", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander2-0xA6512F30_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander2-0xA6512F30_priv.asc",
                "pep.test.xander.work@pep-project.org", "46A994F19077C05610870273C4B8AB0BA6512F30", 
                PEP_OWN_USERID, "Xander3", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander3-0x724B3975_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander3-0x724B3975_priv.asc",
                "pep.test.xander@pep-project.org", "5F7076BBD92E14EA49F0DF7C2CE49419724B3975", 
                PEP_OWN_USERID, "Xander4", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander4-0x844B9DCF_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander4-0x844B9DCF_priv.asc",
                "pep.test.xander.home@pep-project.org", "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF", 
                PEP_OWN_USERID, "Xander in Wonderland Again", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;
    
    status = _own_keys_retrieve(session, &keylist, 0, true);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(keylist);

    int fpr_count = 0;

    const char* fpr_list[5];
    
    bool* found_list = (bool*)calloc(5, sizeof(bool));
    fpr_list[0] = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB"; 
    fpr_list[1] = "59AF4C51492283522F6904531C09730A541260F6"; 
    fpr_list[2] = "46A994F19077C05610870273C4B8AB0BA6512F30"; 
    fpr_list[3] = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975"; 
    fpr_list[4] = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF"; 
     
    for (stringlist_t* _kl = keylist; _kl; _kl = _kl->next) {
        TEST_ASSERT(_kl->value);
        fpr_count++;
        
        for (int j = 0; j < 5; j++) {
            if (strcmp(_kl->value, fpr_list[j]) == 0) {
                found_list[j] = true;
                break;
            }
        }
    }
    TEST_ASSERT_MSG(fpr_count == 5, "Returned keylist does not have the correct number of keys.");
    for (int j = 0; j < 5; j++) {
        TEST_ASSERT_MSG(found_list[j], (string(fpr_list[j]) + " was not found.").c_str());
    }    
    free(found_list);
    free_stringlist(keylist);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_multiple_private_and_pub() {
    // Setup own identity
    PEP_STATUS status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander0-0x3B7302DB_priv.asc",
                "pep.test.xander@pep-project.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB", 
                PEP_OWN_USERID, "Xander in Wonderland", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc");
    
    // Make it an own identity in the DB
    pEp_identity* me_pub = new_identity("pep.test.xander@pep-project.org", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander1-0x541260F6_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander1-0x541260F6_priv.asc",
                "pep.test.xander@pep-project.org", "59AF4C51492283522F6904531C09730A541260F6", 
                PEP_OWN_USERID, "Xander2", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.xander@pep-project.org", "74D79B4496E289BD8A71B70BA8E2C4530019697D", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;


    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander2-0xA6512F30_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander2-0xA6512F30_priv.asc",
                "pep.test.xander.work@pep-project.org", "46A994F19077C05610870273C4B8AB0BA6512F30", 
                PEP_OWN_USERID, "Xander3", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.xander@pep-project.org", "2E21325D202A44BFD9C607FCF095B202503B14D8", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;


    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander3-0x724B3975_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander3-0x724B3975_priv.asc",
                "pep.test.xander@pep-project.org", "5F7076BBD92E14EA49F0DF7C2CE49419724B3975", 
                PEP_OWN_USERID, "Xander4", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.xander@pep-project.org", "3C1E713D8519D7F907E3142D179EAA24A216E95A", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;

    // Setup own identity
    status = read_file_and_import_key(session,
                "test_keys/pub/pep.test.alexander4-0x844B9DCF_pub.asc");
    TEST_ASSERT(status == PEP_KEY_IMPORTED);
    status = set_up_ident_from_scratch(session,
                "test_keys/priv/pep.test.alexander4-0x844B9DCF_priv.asc",
                "pep.test.xander.home@pep-project.org", "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF", 
                PEP_OWN_USERID, "Xander in Wonderland Again", NULL, true
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    
    // Ok, see if we get it back.
    stringlist_t* keylist = NULL;
    
    status = _own_keys_retrieve(session, &keylist, 0, true);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(keylist);

    int fpr_count = 0;

    const char* fpr_list[5];
    
    bool* found_list = (bool*)calloc(5, sizeof(bool));
    fpr_list[0] = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB"; 
    fpr_list[1] = "59AF4C51492283522F6904531C09730A541260F6"; 
    fpr_list[2] = "46A994F19077C05610870273C4B8AB0BA6512F30"; 
    fpr_list[3] = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975"; 
    fpr_list[4] = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF"; 
     
    for (stringlist_t* _kl = keylist; _kl; _kl = _kl->next) {
        TEST_ASSERT(_kl->value);
        fpr_count++;
        
        for (int j = 0; j < 5; j++) {
            if (strcmp(_kl->value, fpr_list[j]) == 0) {
                found_list[j] = true;
                break;
            }
        }
    }
    TEST_ASSERT_MSG(fpr_count == 5, "Returned keylist does not have the correct number of keys.");
    for (int j = 0; j < 5; j++) {
        TEST_ASSERT_MSG(found_list[j], (string(fpr_list[j]) + " was not found.").c_str());
    }    
    free(found_list);
    free_stringlist(keylist);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_multi_pub_only() {
        
    PEP_STATUS status = set_up_ident_from_scratch(session,
                "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc",
                "pep.test.alexander0@darthmama.org", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB", 
                PEP_OWN_USERID, "Xander in Wonderland", NULL, false
            );
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    // Make it an own identity in the DB
    pEp_identity* me_pub = new_identity("pep.test.alexander0@darthmama.org", NULL, PEP_OWN_USERID, NULL);
    status = update_identity(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(strcmp(me_pub->fpr, "F4598A17D4690EB3B5B0F6A344F04E963B7302DB") == 0);
    status = trust_personal_key(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);
    
    me_pub->me = true;
    status = set_identity(session, me_pub);
    free_identity(me_pub);
    me_pub = NULL;
    TEST_ASSERT(status == PEP_STATUS_OK);


    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "74D79B4496E289BD8A71B70BA8E2C4530019697D", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "2E21325D202A44BFD9C607FCF095B202503B14D8", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;

    // Own pub key
    TEST_ASSERT_MSG(slurp_and_import_key(session, "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc"),
                    "Unable to import test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc");
    
    // Make it an own identity in the DB
    me_pub = new_identity("pep.test.alexander0@darthmama.org", "3C1E713D8519D7F907E3142D179EAA24A216E95A", PEP_OWN_USERID, NULL);
    me_pub->comm_type = PEP_ct_pEp;
    status = set_trust(session, me_pub);
    TEST_ASSERT(status == PEP_STATUS_OK);    
    free_identity(me_pub);
    me_pub = NULL;
    
    // Ok, see if we get anything back.
    stringlist_t* keylist = NULL;
    
    status = _own_keys_retrieve(session, &keylist, 0, true);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(!keylist);

    free_stringlist(keylist);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_no_own() {
    TEST_ASSERT(true);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_multi_idents_one_key() {
    TEST_ASSERT(true);
}

void OwnKeysRetrieveTests::check_own_keys_retrieve_multi_idents_one_priv_key_multi_pub() {
    TEST_ASSERT(true);
}
