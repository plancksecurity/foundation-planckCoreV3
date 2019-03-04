// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include <cpptest.h>

#include <cstring>

#include "pEpEngine.h"
#include "TestUtils.h"
#include "pEpTestDevice.h"

#include "EngineTestIndividualSuite.h"
#include "SyncDeviceTests.h"

using namespace std;

SyncDeviceTests::SyncDeviceTests(string suitename, string test_home_dir)  :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir, false) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SyncDeviceTests::check_sync_two_devices"),
                                                                      static_cast<Func>(&SyncDeviceTests::check_sync_two_devices)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SyncDeviceTests::check_sync_three_devices"),
                                                                      static_cast<Func>(&SyncDeviceTests::check_sync_three_devices)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SyncDeviceTests::check_sync_two_grouped_devices"),
                                                                      static_cast<Func>(&SyncDeviceTests::check_sync_two_grouped_devices)));
}

void SyncDeviceTests::setup() {
    EngineTestIndividualSuite::setup();
}

void SyncDeviceTests::tear_down() {
    for (vector<pEpTestDevice*>::iterator it = device_queue.begin();
         it != device_queue.end(); it++) {
        delete(*it);
    }
    device_queue.clear();
    EngineTestIndividualSuite::tear_down();
}

void SyncDeviceTests::check_sync_two_devices(){
    PEP_STATUS status = PEP_STATUS_OK;

    pEpTestDevice* first;
    pEpTestDevice* second;
    
    device_queue.push_back(first = new pEpTestDevice(temp_test_home, "One"));
    string mbox = first->device_dir + "/mbox";
    first->set_mailbox_dir(mbox);
    
    device_queue.push_back(second = new pEpTestDevice(temp_test_home, "Two"));

    second->set_mailbox_dir(mbox);
    first->address_to_mbox_map = second->address_to_mbox_map =
        {{"owen.corley@fort-tarsis.darthmama.org", mbox}};
    
    const char* addr = "owen.corley@fort-tarsis.darthmama.org";
    const char* uname_1 = "Owen Corley";
    const char* uname_2 = "Owen 'Sandwiches' Corley";
    const char* uid1 = "Owen_One";
    const char* uid2 = "Owen_Two";
    
    pEpTestDevice::switch_context(first);
    pEp_identity* owen_first = new_identity(addr, NULL, uid1, uname_1);
    status = myself(first->session, owen_first);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(owen_first->fpr && *(owen_first->fpr) != '\0');
    string owen_1_fpr = owen_first->fpr;    
        
    pEpTestDevice::switch_context(second);
    pEp_identity* owen_second = new_identity(addr, NULL, uid2, uname_2);
    status = myself(second->session, owen_second);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(owen_second->fpr && *(owen_second->fpr) != '\0');
    string owen_2_fpr = owen_second->fpr;    

    TEST_ASSERT_MSG(owen_1_fpr.compare(owen_2_fpr) != 0,
                    "Only one fpr generated for two separate devices. This is a pEpTestDevice error.");
                    
    // Ok, so... let's do this? Send to myself. Why not.
    message* trigger_msg = new_message(PEP_dir_outgoing);
    trigger_msg->from = identity_dup(owen_second);
    trigger_msg->to = new_identity_list(new_identity(addr, NULL, uid2, uname_2));
    trigger_msg->shortmsg = strdup("Remember! Javelins look cool!");
    trigger_msg->longmsg = strdup("Make sure to tell the Freelancer her interceptor looks better with a gold butt.\n");
    trigger_msg->attachments = new_bloblist(NULL, 0, "application/octet-stream", NULL);
                
    message* enc_msg = NULL;
    status = encrypt_message(pEpTestDevice::active->session, trigger_msg, NULL,
                             &enc_msg, PEP_enc_PGP_MIME, 0);
    
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));                                 
    TEST_ASSERT(enc_msg);
    
    pEpTestDevice::active->add_message_to_send_queue(enc_msg);
    TEST_ASSERT_MSG(pEpTestDevice::active->send_queue.size() > 0,
                    "Empty send queue!!! :(");
    
    pEpTestDevice::switch_context(first);

    vector<string> inbox_list;
    vector<message*> inbox_mails;
    
    pEpTestDevice::active->check_mail(inbox_list);
    TEST_ASSERT(inbox_list.size() > 0);    
    pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
    TEST_ASSERT(inbox_mails.size() > 0);
    
    vector<message*> decrypted_mails;
    
    stringlist_t* keylist = NULL;
    PEP_rating rating;
    PEP_decrypt_flags_t flags = 0;     
    message* dec_msg = NULL;

    status = decrypt_message(pEpTestDevice::active->session,
                             inbox_mails.at(0), &dec_msg, &keylist,
                             &rating, &flags);

    TEST_ASSERT(status == PEP_DECRYPT_NO_KEY);

    free_stringlist(keylist);
    inbox_list.clear();
    clear_message_vector(inbox_mails);

    // Ok, we couldn't decrypt the message. So, uh, let's see what sync does
    pEpTestDevice::switch_context(second);
    
    pEpTestDevice::active->check_mail(inbox_list);
    TEST_ASSERT(inbox_list.size() > 0);    
    pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
    TEST_ASSERT(inbox_mails.size() > 0);
    
//    vector<message*> decrypted_mails;
    
    keylist = NULL;
    flags = 0;     
    dec_msg = NULL;

    status = decrypt_message(pEpTestDevice::active->session,
                             inbox_mails.at(0), &dec_msg, &keylist,
                             &rating, &flags);

    TEST_ASSERT(status == PEP_STATUS_OK);

    free_stringlist(keylist);
    keylist = NULL;
    flags = 0;
    free_message(dec_msg);
    dec_msg = NULL;

    status = decrypt_message(pEpTestDevice::active->session,
                             inbox_mails.at(1), &dec_msg, &keylist,
                             &rating, &flags);

    TEST_ASSERT_MSG(status == PEP_UNENCRYPTED, tl_status_string(status));

    TEST_ASSERT(inbox_mails.size() == 2);

    // Ok, let's let these bad boys talk back and forth 
    bool all_clear = false;
    do {
        for (int i = 0; i < 2; i++) {
            inbox_list.clear();
            clear_message_vector(inbox_mails);    

            pEpTestDevice* switch_to =
                (i % 2 ? second : first);
            pEpTestDevice::switch_context(switch_to);

            pEpTestDevice::active->check_mail(inbox_list);
            cout << "inbox_list size is " << inbox_list.size() << endl;
            cout << "i = " << i << endl;
            cout << "all_clear = " << all_clear << endl;
            if (inbox_list.empty() && (i == 0 || all_clear)) {
                cout << "Setting all_clear to true" << endl;
                all_clear = true;
                continue;
            }
            else {
                cout << "Setting all_clear to false" << endl;
                all_clear = false;
            }
                
            pEpTestDevice::active->read_mail(inbox_list, inbox_mails);
            cout << "Inbox mails size is " << inbox_mails.size() << endl;
            vector<string>::iterator fp = inbox_list.begin();
            cout << "WHAT" << endl;
            for (vector<message*>::iterator it = inbox_mails.begin();
                it != inbox_mails.end(); it++) {
                cout << "HELLO!" << endl;
                free_stringlist(keylist);                
                keylist = NULL;
                flags = 0;
                free_message(dec_msg);                      
                dec_msg = NULL;
                 
                status = decrypt_message(pEpTestDevice::active->session,
                                         *it, &dec_msg, &keylist,
                                         &rating, &flags);
                cout << "flags! : " << flags << endl;
                TEST_ASSERT(status == PEP_UNENCRYPTED);
                stringpair_list_t* opt_fields = (*it)->opt_fields;
                while (opt_fields && opt_fields->value && opt_fields->value->key && opt_fields->value->value) {
                    if (strcmp(opt_fields->value->key, "pEp-auto-consume") == 0 &&
                        strcmp(opt_fields->value->value, "yes") == 0) {
                        pEpTestDevice::active->delete_mail(*fp);    
                        break;
                    }
                    opt_fields = opt_fields->next;
                }
                fp++;
            }
            free_stringlist(keylist);                
            keylist = NULL;
            flags = 0;
            free_message(dec_msg);                      
            dec_msg = NULL;
        }
    } while (!all_clear);
    
    // inbox_list.clear();
    // free(inbox_mails.at(0));
    // inbox_mails.clear();    
    // 
    // switch_context(second);

    
//    TEST_ASSERT(pEpTestDevice::active->send_queue.size() == 1);
}

void SyncDeviceTests::check_sync_three_devices(){
    TEST_ASSERT(true);
}

void SyncDeviceTests::check_sync_two_grouped_devices(){
    TEST_ASSERT(true);
}
