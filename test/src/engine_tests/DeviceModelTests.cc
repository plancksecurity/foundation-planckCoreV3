// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>

#include "pEpEngine.h"

#include "TestUtils.h"
#include "EngineTestIndividualSuite.h"
#include "DeviceModelTests.h"
#include <cpptest.h>
#include <cstring>

using namespace std;

DeviceModelTests::DeviceModelTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir, false) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_device_model"),
                                                                      static_cast<Func>(&DeviceModelTests::check_device_model)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_two_device_model"),
                                                                      static_cast<Func>(&DeviceModelTests::check_two_device_model)));
}

void DeviceModelTests::check_device_model() {
    pEpTestDevice* single = new pEpTestDevice(temp_test_home, "SingleDevice");
    TEST_ASSERT_MSG(device == NULL, "EngineTestSuite created device when it should not have.");
    TEST_ASSERT_MSG(session == NULL, "EngineTestSuite has a default session - not cool.");    
    TEST_ASSERT_MSG(single->session, "Device has no session.");

    single->set_mailbox_dir(single->device_dir + "/mbox");
    const string mbox_dir = single->mbox_dir;
    struct stat dirchk;
    TEST_ASSERT_MSG(stat(mbox_dir.c_str(), &dirchk) == 0,
                    "Device mbox dir not created.");
    TEST_ASSERT_MSG(S_ISDIR(dirchk.st_mode), "Device mbox dir exists, but isn't a directory.");                

    const string device_dir = string(single->device_dir);
    delete(single);
    
    TEST_ASSERT_MSG(stat(device_dir.c_str(), &dirchk) != 0,
                         "Device dir not removed.");
}

void DeviceModelTests::check_two_device_model() {
    pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "First");
    first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    string homedir = getenv("HOME");
    TEST_ASSERT_MSG(strcmp(homedir.c_str(), first_device->device_dir.c_str()) == 0, "First device didn't set $HOME correctly.");
    string gpgdir = getenv("GNUPGHOME");
    TEST_ASSERT_MSG(strcmp(gpgdir.c_str(), (first_device->device_dir + "/gnupg").c_str()) == 0, "First device didn't set $GNUPGHOME correctly.");    
    first_device->unset_device_environment();
    pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Second");
    homedir = getenv("HOME");
    TEST_ASSERT_MSG(strcmp(homedir.c_str(), second_device->device_dir.c_str()) == 0, "Second device didn't set $HOME correctly");
    gpgdir = getenv("GNUPGHOME");
    TEST_ASSERT_MSG(strcmp(gpgdir.c_str(), (second_device->device_dir + "/gnupg").c_str()) == 0, "Second device didn't set $GNUPGHOME correctly.");    
    second_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    first_device->grab_context(second_device);
    homedir = getenv("HOME");
    TEST_ASSERT_MSG(strcmp(homedir.c_str(), first_device->device_dir.c_str()) == 0, "First device failed to grab context.");
    gpgdir = getenv("GNUPGHOME");
    TEST_ASSERT_MSG(strcmp(gpgdir.c_str(), (first_device->device_dir + "/gnupg").c_str()) == 0, "First device context switch didn't set $GNUPGHOME correctly.");    
    second_device->grab_context(first_device);
    homedir = getenv("HOME");
    TEST_ASSERT_MSG(strcmp(homedir.c_str(), second_device->device_dir.c_str()) == 0, "Second device failed to grab context.");
    gpgdir = getenv("GNUPGHOME");
    TEST_ASSERT_MSG(strcmp(gpgdir.c_str(), (second_device->device_dir + "/gnupg").c_str()) == 0, "Second device context switch didn't set $GNUPGHOME correctly.");        
    delete(first_device);
    delete(second_device);
    TEST_ASSERT(true);
}

void DeviceModelTests::check_two_device_functionality() {
    // Set up devices and shared mailbox
    pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "First");
    first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    first_device->unset_device_environment();
    pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Second");
    second_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    first_device->grab_context(second_device);
    TEST_ASSERT_MSG(first_device->mbox_dir.compare(second_device->mbox_dir) == 0,
                    "Shared mailbox is not really shared");

    string alice_email = "pep.test.alice@pep-project.org";
    string alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    
    // First device is Alice's established one with the current key
    TEST_ASSERT_MSG(slurp_and_import_key(first_device->session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"),
                    "Alice's pubkey not imported for first device.");
    TEST_ASSERT_MSG(slurp_and_import_key(first_device->session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"),
                    "Alice's privkey not imported for first device.");

    pEp_identity* alice_dev_1_ident = new_identity(alice_email.c_str(), alice_fpr.c_str(), "ALICE", "Alice From Mel's Diner");
    
    PEP_STATUS status = set_own_key(first_device->session, alice_dev_1_ident, alice_fpr.c_str());    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, 
        (string("Unable to set own key on first device. status is ") + tl_status_string(status)).c_str());

    free(alice_dev_1_ident->fpr);
    alice_dev_1_ident->fpr = NULL;
    status = myself(first_device->session, alice_dev_1_ident);
    TEST_ASSERT(alice_dev_1_ident->fpr);
    TEST_ASSERT_MSG(alice_fpr.compare(alice_dev_1_ident->fpr) == 0,
                    "set_own_key does not seem to have set alice's key for device 1.");
                
    second_device->grab_context(first_device);

    pEp_identity* alice_dev_2_ident = new_identity(alice_email.c_str(), NULL, PEP_OWN_USERID, "Alice Miller");
    // Second device is one Alice is setting up (we'll use this model for keysync tests, so why not?)

    status = myself(second_device->session, alice_dev_2_ident);

    TEST_ASSERT_MSG(alice_dev_2_ident->fpr, "No fpr for alice on second device");
    TEST_ASSERT_MSG(alice_fpr.compare(alice_dev_2_ident->fpr) != 0,
                    "myself did not generate new key for alice on device 2; alice's old key was found.");
    
    const char* alice_2_fpr = alice_dev_2_ident->fpr;
    
    first_device->grab_context(second_device);
    
    stringlist_t* keylist = NULL;
    
    status = find_keys(first_device->session, alice_2_fpr, &keylist);
    
    TEST_ASSERT(!keylist);
    TEST_ASSERT(status == PEP_KEY_NOT_FOUND);
    free_stringlist(keylist);
    keylist = NULL;

    second_device->grab_context(first_device);
    
    char* alice_2_keydata = NULL;
    size_t alice_2_keydata_size = 0;
    
    status = export_key(session, alice_2_fpr, &alice_2_keydata, &alice_2_keydata_size);

    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(alice_2_keydata);
    
    first_device->grab_context(second_device);

    status = import_key(first_device->session, alice_2_keydata, alice_2_keydata_size, NULL);

    free(alice_2_keydata);
    alice_2_keydata = NULL;

    status = find_keys(first_device->session, alice_2_fpr, &keylist);    
    TEST_ASSERT(keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    free_stringlist(keylist);
    keylist = NULL;

    second_device->grab_context(first_device);
    TEST_ASSERT_MSG(slurp_and_import_key(second_device->session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"),
                    "Alice's first pubkey not imported for second device.");

    // Ok, so, we're relatively certain we have all that set up. Now let's have both
    // import Bob's key, but only one of them trust it. Then we're sure we have 
    // different, functioning trust dbs, and we're done with this case and ready 
    // to move on to checking mboxes
    string bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
    TEST_ASSERT_MSG(slurp_and_import_key(second_device->session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"), 
                    "Second device couldn't import Bob's pubkey");
    pEp_identity* bob_id = new_identity("pep.test.bob@pep-project.org", NULL, NULL, "Bob Barker");    
    status = update_identity(second_device->session, bob_id);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(bob_id->fpr);
    TEST_ASSERT(bob_fpr.compare(bob_id->fpr) == 0);

    status = trust_personal_key(second_device->session, bob_id);
    TEST_ASSERT(status == PEP_STATUS_OK);
    status = update_identity(second_device->session, bob_id);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(bob_id->comm_type == PEP_ct_OpenPGP);    
    
    first_device->grab_context(second_device);
    TEST_ASSERT_MSG(slurp_and_import_key(first_device->session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc"), 
                    "First device couldn't import Bob's pubkey");
    pEp_identity* bob_id_2 = new_identity("pep.test.bob@pep-project.org", NULL, NULL, "Bob Barker");    
    status = update_identity(first_device->session, bob_id_2);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(bob_id_2->comm_type == PEP_ct_OpenPGP_unconfirmed);    

    free_identity(alice_dev_1_ident);                  
    free_identity(alice_dev_2_ident);
    free_identity(bob_id);
    free_identity(bob_id_2);              
    delete(first_device);
    delete(second_device);
}

void DeviceModelTests::check_shared_mbox() {
    // Set up devices and shared mailbox
    pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "First");
    first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    first_device->unset_device_environment();
    pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Second");
    second_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    first_device->grab_context(second_device);
    TEST_ASSERT_MSG(first_device->mbox_dir.compare(second_device->mbox_dir) == 0,
                    "Shared mailbox is not really shared");

    string alice_email = "pep.test.alice@pep-project.org";
    string alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    
    // First device is Alice's established one with the current key
    TEST_ASSERT_MSG(slurp_and_import_key(first_device->session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc"),
                    "Alice's pubkey not imported for first device.");
    TEST_ASSERT_MSG(slurp_and_import_key(first_device->session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc"),
                    "Alice's privkey not imported for first device.");

    pEp_identity* alice_dev_1_ident = new_identity(alice_email.c_str(), alice_fpr.c_str(), "ALICE", "Alice From Mel's Diner");
    
    PEP_STATUS status = set_own_key(first_device->session, alice_dev_1_ident, alice_fpr.c_str());    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, 
        (string("Unable to set own key on first device. status is ") + tl_status_string(status)).c_str());

    // Second device is one Alice is setting up (we'll use this model for keysync tests, so why not?)                
    second_device->grab_context(first_device);

    pEp_identity* alice_dev_2_ident = new_identity(alice_email.c_str(), NULL, PEP_OWN_USERID, "Alice Miller");

    status = myself(second_device->session, alice_dev_2_ident);

    TEST_ASSERT_MSG(alice_dev_2_ident->fpr, "No fpr for alice on second device");
    TEST_ASSERT_MSG(alice_fpr.compare(alice_dev_2_ident->fpr) != 0,
                    "myself did not generate new key for alice on device 2; alice's old key was found.");
    
    const char* alice_2_fpr = alice_dev_2_ident->fpr;
    
    // Ok, everybody's set up. Let's play with mailboxes.
    
    first_device->grab_context(second_device);
    
    
}
