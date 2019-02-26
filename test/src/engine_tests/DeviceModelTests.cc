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
#include "mime.h"

#include "TestUtils.h"
#include "EngineTestIndividualSuite.h"
#include "DeviceModelTests.h"
#include <cpptest.h>
#include <cstring>

using namespace std;

static void remove_sync_mails(vector<message*> &mails) {
    for (vector<message*>::iterator it = mails.begin(); it != mails.end(); ) {
        stringpair_list_t* opt_fields = (*it)->opt_fields;
        bool erased = false;
        while (opt_fields && opt_fields->value && opt_fields->value->key && opt_fields->value->value) {
            if (strcmp(opt_fields->value->key, "pEp-auto-consume") == 0 &&
                strcmp(opt_fields->value->value, "yes") == 0) {
                it = mails.erase(it);
                erased = true;
            }
            opt_fields = opt_fields->next;
        }
        if (!erased)
            it++;
    }
}

DeviceModelTests::DeviceModelTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir, false) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_device_model"),
                                                                      static_cast<Func>(&DeviceModelTests::check_device_model)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_two_device_model"),
                                                                      static_cast<Func>(&DeviceModelTests::check_two_device_model)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_two_device_functionality"),
                                                                      static_cast<Func>(&DeviceModelTests::check_two_device_functionality)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_mbox"),
                                                                      static_cast<Func>(&DeviceModelTests::check_mbox)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_three_device_mbox_with_send"),
                                                                      static_cast<Func>(&DeviceModelTests::check_three_device_mbox_with_send)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("DeviceModelTests::check_switch_context"),
                                                                      static_cast<Func>(&DeviceModelTests::check_switch_context)));
}

void DeviceModelTests::setup() {
    EngineTestIndividualSuite::setup();
    pEpTestDevice::active = NULL;
}

void DeviceModelTests::tear_down() {
    for (vector<pEpTestDevice*>::iterator it = devices.begin();
                                         it != devices.end(); it++)
        delete(*it);                                         
    devices.clear();
    EngineTestIndividualSuite::tear_down();
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
    devices.push_back(first_device);
    first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    string homedir = getenv("HOME");
    TEST_ASSERT_MSG(strcmp(homedir.c_str(), first_device->device_dir.c_str()) == 0, "First device didn't set $HOME correctly.");
    string gpgdir = getenv("GNUPGHOME");
    TEST_ASSERT_MSG(strcmp(gpgdir.c_str(), (first_device->device_dir + "/gnupg").c_str()) == 0, "First device didn't set $GNUPGHOME correctly.");    

    pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Second");
    devices.push_back(second_device);
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
}

void DeviceModelTests::check_two_device_functionality() {
    // Set up devices and shared mailbox
    pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "First");
    devices.push_back(first_device);    
    first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
    
    pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Second");
    devices.push_back(second_device);    
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
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    free_stringlist(keylist);
    keylist = NULL;

    second_device->grab_context(first_device);
    
    char* alice_2_keydata = NULL;
    size_t alice_2_keydata_size = 0;
    
    status = export_key(second_device->session, alice_2_fpr, &alice_2_keydata, &alice_2_keydata_size);

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
}

void DeviceModelTests::check_mbox() {
    // Set up devices and shared mailbox
    pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "Device");
    devices.push_back(first_device);
    
    first_device->set_mailbox_dir(first_device->device_dir + "/mbox");

    string alice_email = "pep.test.alice@pep-project.org";
    string alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    
    slurp_and_import_key(first_device->session, "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc");
    slurp_and_import_key(first_device->session, "test_keys/priv/pep-test-alice-0x6FF00E97_priv.asc");
    
    pEp_identity* alice_ident = new_identity(alice_email.c_str(), alice_fpr.c_str(), "ALICE", "Alice From Mel's Diner");    
    PEP_STATUS status = set_own_key(first_device->session, alice_ident, alice_fpr.c_str());    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, 
        (string("Unable to set own key. status is ") + tl_status_string(status)).c_str());
        
    message* new_msg = new_message(PEP_dir_outgoing);
    
    new_msg->from = alice_ident;
    new_msg->to = new_identity_list(identity_dup(alice_ident));
    new_msg->longmsg = strdup("Some dumb message.\nBlahblahblah.");
    new_msg->shortmsg = strdup("hello, world");
    new_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

    message* enc_msg = NULL;
    
    status = encrypt_message(first_device->session, new_msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);

    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(enc_msg);
    char* msg_text = NULL;
    mime_encode_message(enc_msg, false, &msg_text);
    TEST_ASSERT(msg_text);
    
    string filename = first_device->receive_mail(msg_text);
    TEST_ASSERT(!filename.empty());

    vector<string> curr_mail_received;
    first_device->check_mail(curr_mail_received);
    TEST_ASSERT_MSG(curr_mail_received.size() == 1, 
                    (string("Received ") + to_string(curr_mail_received.size()) + " emails, should have received 1.").c_str());

    first_device->receive_mail(msg_text);
    first_device->receive_mail(msg_text);
    first_device->receive_mail(msg_text);
    first_device->check_mail(curr_mail_received);
    TEST_ASSERT_MSG(curr_mail_received.size() == 3, 
                    (string("Received ") + to_string(curr_mail_received.size()) + " emails, should have received 3.").c_str());
    
    first_device->receive_mail(msg_text);
    first_device->receive_mail(msg_text);
    first_device->check_mail(curr_mail_received);
    TEST_ASSERT_MSG(curr_mail_received.size() == 2, 
                    (string("Received ") + to_string(curr_mail_received.size()) + " emails, should have received 2.").c_str());
}

void DeviceModelTests::check_three_device_mbox_with_send() {
    try {
        // Set up devices and shared mailbox
        pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "Alex");
        devices.push_back(first_device);    
        first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
        string alex_email = "alex@darthmama.cool";
        pEp_identity* alex_identity = new_identity(alex_email.c_str(), NULL, "AlexID", "Alex Braithwaite");
        PEP_STATUS status = myself(first_device->session, alex_identity);
        
        pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Bree");
        devices.push_back(second_device);    
        second_device->set_mailbox_dir(second_device->device_dir + "/mbox");
        string bree_email = "bree@cheese.melted";
        pEp_identity* bree_identity = new_identity(bree_email.c_str(), NULL, "BreeID", "Briana Cheeserton");
        status = myself(second_device->session, bree_identity);
        
        pEpTestDevice* third_device = new pEpTestDevice(temp_test_home, "Charmander");
        devices.push_back(third_device);    
        third_device->set_mailbox_dir(third_device->device_dir + "/mbox");
        string charm_email = "charmander@poke.mon";
        pEp_identity* charm_identity = new_identity(charm_email.c_str(), NULL, "CharmID", "Charmander T. Pokemon");
        status = myself(third_device->session, charm_identity);
        first_device->grab_context(third_device);

        map<string,string> address_maps = {
            {alex_email,first_device->mbox_dir},
            {bree_email,second_device->mbox_dir},
            {charm_email,third_device->mbox_dir},
        };

        // this just simulates the ability to address and deliver, so everyone has
        // the same maps.
        first_device->address_to_mbox_map = second_device->address_to_mbox_map =
            third_device->address_to_mbox_map = address_maps;
        // Note to self - I'll bet this is some C++ mem nightmare.
        
        message* msg = new_message(PEP_dir_outgoing);
        msg->from = identity_dup(alex_identity);
        msg->to = new_identity_list(new_identity(bree_email.c_str(), NULL, "ItsBree", "Bree Cheeserton"));
        msg->shortmsg = strdup("First test message!");
        msg->longmsg = strdup("Yo Bree! This is Alex! Hi!\nEr, hi!\n");
        msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

        // engine_passthrough
        message* enc_msg = NULL;
        status = encrypt_message(first_device->session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(enc_msg == NULL);

        // when sent, msg is freed, so do NOT free it after this.
        first_device->add_message_to_send_queue(msg);
        second_device->grab_context(first_device);
        msg = NULL;
        
        vector<string> inbox_list;
        second_device->check_mail(inbox_list);

        vector<message*> inbox_mails;
        stringlist_t* keylist = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags;
        
        second_device->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);
        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        // Get Alex's key
        status = decrypt_message(second_device->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(msg == NULL);

        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();
        
        third_device->grab_context(second_device);
            
        msg = new_message(PEP_dir_outgoing);
        msg->from = identity_dup(charm_identity);
        msg->to = new_identity_list(new_identity(bree_email.c_str(), NULL, "SuperBree", "Bree Cheeserton"));
        msg->shortmsg = strdup("First test message!");
        msg->longmsg = strdup("Yo Bree! This is Charmander! I'm a cool Pokemon! Hi!\nEr, hi!\n");
        msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

        // engine_passthrough
        enc_msg = NULL;
        status = encrypt_message(third_device->session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(enc_msg == NULL);

        // when sent, msg is freed, so do NOT free it after this.
        third_device->add_message_to_send_queue(msg);
        second_device->grab_context(third_device);
        msg = NULL;
            
        second_device->check_mail(inbox_list);
            
        keylist = NULL;
        flags = 0;
        
        second_device->read_mail(inbox_list, inbox_mails);
        
        remove_sync_mails(inbox_mails);
        
        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        // Get Charmander's key
        status = decrypt_message(second_device->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(msg == NULL);

        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();    

        // Ok, now, revenge of encrypting Bree
        msg = new_message(PEP_dir_outgoing);
        msg->from = identity_dup(bree_identity);
        msg->to = new_identity_list(new_identity(alex_email.c_str(), NULL, "Alexei", "Alex Braithwaite is a char in a bad novel"));
        identity_list_add(msg->to, new_identity(charm_email.c_str(), NULL, "Charming", "Charmanderpoke E. Mon is NOT a Pokemon"));
        msg->shortmsg = strdup("Last test message!");
        msg->longmsg = strdup("You guys are fools :)\n");
        msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

        enc_msg = NULL;
        status = encrypt_message(second_device->session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
        TEST_ASSERT(status == PEP_STATUS_OK);
        TEST_ASSERT(enc_msg);
         
        free_message(msg);
        msg = NULL;
        free_stringlist(keylist);
        flags = 0;
        keylist = NULL;
        
        // when sent, enc_msg is freed, so do NOT free it after this.
        second_device->add_message_to_send_queue(enc_msg);
        first_device->grab_context(second_device);
        enc_msg = NULL;

        first_device->check_mail(inbox_list);            
        first_device->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);
        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        status = decrypt_message(first_device->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
        TEST_ASSERT_MSG(rating == PEP_rating_reliable, tl_rating_string(rating));
        TEST_ASSERT(msg);

        free_message(msg);
        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();    

        msg = NULL;
        free_stringlist(keylist);
        flags = 0;
        keylist = NULL;
        
        third_device->grab_context(first_device);

        third_device->check_mail(inbox_list);
            
        third_device->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);

        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        status = decrypt_message(third_device->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
        TEST_ASSERT_MSG(rating == PEP_rating_reliable, tl_rating_string(rating));
        TEST_ASSERT(msg);

        free_message(msg);
        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();    
        free_stringlist(keylist);
    }
    catch (const runtime_error& error) {
        TEST_ASSERT_MSG(false, error.what());
    }
}

void DeviceModelTests::check_switch_context() {
    try {
        // Set up devices and shared mailbox
        pEpTestDevice* first_device = new pEpTestDevice(temp_test_home, "Alex");
        devices.push_back(first_device);    
        first_device->set_mailbox_dir(first_device->device_dir + "/mbox");
        string alex_email = "alex@darthmama.cool";
        pEp_identity* alex_identity = new_identity(alex_email.c_str(), NULL, "AlexID", "Alex Braithwaite");
        PEP_STATUS status = myself(first_device->session, alex_identity);
        
        pEpTestDevice* second_device = new pEpTestDevice(temp_test_home, "Bree");
        devices.push_back(second_device);    
        second_device->set_mailbox_dir(second_device->device_dir + "/mbox");
        string bree_email = "bree@cheese.melted";
        pEp_identity* bree_identity = new_identity(bree_email.c_str(), NULL, "BreeID", "Briana Cheeserton");
        status = myself(second_device->session, bree_identity);
        
        pEpTestDevice* third_device = new pEpTestDevice(temp_test_home, "Charmander");
        devices.push_back(third_device);    
        third_device->set_mailbox_dir(third_device->device_dir + "/mbox");
        string charm_email = "charmander@poke.mon";
        pEp_identity* charm_identity = new_identity(charm_email.c_str(), NULL, "CharmID", "Charmander T. Pokemon");
        status = myself(third_device->session, charm_identity);
        
        pEpTestDevice::switch_context(first_device);

        map<string,string> address_maps = {
            {alex_email,first_device->mbox_dir},
            {bree_email,second_device->mbox_dir},
            {charm_email,third_device->mbox_dir},
        };

        // this just simulates the ability to address and deliver, so everyone has
        // the same maps.
        first_device->address_to_mbox_map = second_device->address_to_mbox_map =
            third_device->address_to_mbox_map = address_maps;
        // Note to self - I'll bet this is some C++ mem nightmare.
        
        message* msg = new_message(PEP_dir_outgoing);
        msg->from = identity_dup(alex_identity);
        msg->to = new_identity_list(new_identity(bree_email.c_str(), NULL, "ItsBree", "Bree Cheeserton"));
        msg->shortmsg = strdup("First test message!");
        msg->longmsg = strdup("Yo Bree! This is Alex! Hi!\nEr, hi!\n");
        msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

        // engine_passthrough
        message* enc_msg = NULL;
        status = encrypt_message(pEpTestDevice::active->session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(enc_msg == NULL);

        // when sent, msg is freed, so do NOT free it after this.
        pEpTestDevice::active->add_message_to_send_queue(msg);
        pEpTestDevice::switch_context(second_device);

        msg = NULL;
        
        vector<string> inbox_list;
        pEpTestDevice::active->check_mail(inbox_list);

        vector<message*> inbox_mails;
        stringlist_t* keylist = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags;
        pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);

        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        // Get Alex's key
        status = decrypt_message(pEpTestDevice::active->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(msg == NULL);

        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();
        
        pEpTestDevice::switch_context(third_device);
            
        msg = new_message(PEP_dir_outgoing);
        msg->from = identity_dup(charm_identity);
        msg->to = new_identity_list(new_identity(bree_email.c_str(), NULL, "SuperBree", "Bree Cheeserton"));
        msg->shortmsg = strdup("First test message!");
        msg->longmsg = strdup("Yo Bree! This is Charmander! I'm a cool Pokemon! Hi!\nEr, hi!\n");
        msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

        // engine_passthrough
        enc_msg = NULL;
        status = encrypt_message(pEpTestDevice::active->session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(enc_msg == NULL);

        // when sent, msg is freed, so do NOT free it after this.
        pEpTestDevice::active->add_message_to_send_queue(msg);

        pEpTestDevice::switch_context(second_device);
        msg = NULL;
            
        pEpTestDevice::active->check_mail(inbox_list);    
        keylist = NULL;
        flags = 0;
        pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);

        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        // Get Charmander's key
        status = decrypt_message(pEpTestDevice::active->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT(status == PEP_UNENCRYPTED);
        TEST_ASSERT(msg == NULL);

        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();    

        // Ok, now, revenge of encrypting Bree
        msg = new_message(PEP_dir_outgoing);
        msg->from = identity_dup(bree_identity);
        msg->to = new_identity_list(new_identity(alex_email.c_str(), NULL, "Alexei", "Alex Braithwaite is a char in a bad novel"));
        identity_list_add(msg->to, new_identity(charm_email.c_str(), NULL, "Charming", "Charmanderpoke E. Mon is NOT a Pokemon"));
        msg->shortmsg = strdup("Last test message!");
        msg->longmsg = strdup("You guys are fools :)\n");
        msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);

        enc_msg = NULL;
        status = encrypt_message(pEpTestDevice::active->session, msg, NULL, &enc_msg, PEP_enc_PGP_MIME, 0);
        TEST_ASSERT(status == PEP_STATUS_OK);
        TEST_ASSERT(enc_msg);
         
        free_message(msg);
        msg = NULL;
        free_stringlist(keylist);
        flags = 0;
        keylist = NULL;
        
        // when sent, enc_msg is freed, so do NOT free it after this.
        pEpTestDevice::active->add_message_to_send_queue(enc_msg);

        pEpTestDevice::switch_context(first_device);
                
        enc_msg = NULL;

        pEpTestDevice::active->check_mail(inbox_list);
            
        pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);
        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        status = decrypt_message(pEpTestDevice::active->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
        TEST_ASSERT_MSG(rating == PEP_rating_reliable, tl_rating_string(rating));
        TEST_ASSERT(msg);

        free_message(msg);
        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();    

        msg = NULL;
        free_stringlist(keylist);
        flags = 0;
        keylist = NULL;
        
        pEpTestDevice::switch_context(third_device);

        pEpTestDevice::active->check_mail(inbox_list);
        pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
        remove_sync_mails(inbox_mails);
        TEST_ASSERT(inbox_mails.size() == 1 && inbox_mails.at(0));
        
        status = decrypt_message(pEpTestDevice::active->session,
                                 inbox_mails.at(0), &msg, &keylist,
                                 &rating, &flags);
        TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
        TEST_ASSERT_MSG(rating == PEP_rating_reliable, tl_rating_string(rating));
        TEST_ASSERT(msg);

        free_message(msg);
        inbox_list.clear();
        free(inbox_mails.at(0));
        inbox_mails.clear();    
        free_stringlist(keylist);
    }
    catch (const runtime_error& error) {
        TEST_ASSERT_MSG(false, error.what());
    }
}
