#include <stdlib.h>
#include <string>
#include <cstring>
#include <ctime>
#include <deque>

#include <sqlite3.h>

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "sync_api.h"
#include "Sync_impl.h"
#include "mime.h"

#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"


#include <gtest/gtest.h>

using namespace boost::interprocess;

//Define an STL compatible allocator of message* that allocates from the managed_shared_memory.
//This allocator will allow placing containers in the segment
typedef boost::interprocess::allocator<std::string, managed_shared_memory::segment_manager>  ShmemAllocator;

//Alias a vector that uses the previous STL-like allocator so that allocates
//its values from the segment
typedef boost::interprocess::vector<std::string, ShmemAllocator> MailList;

class LockedMailList
{
public:
    MailList vec;
    boost::interprocess::interprocess_mutex mutex;

    LockedMailList(ShmemAllocator sm) 
       : vec(sm) 
    {}    
};


PEP_STATUS SyncTwoParty_message_send_callback(message* msg);
int SyncTwoParty_inject_sync_event(SYNC_EVENT ev, void *management);
SYNC_EVENT SyncTwoParty_retrieve_next_sync_event(void *management, unsigned threshold);
PEP_STATUS SyncTwoParty_notify_handshake(pEp_identity *me, pEp_identity *partner, sync_handshake_signal signal);

static void* SyncTwoParty_fake_this;

#define SyncTwoParty_segment_name "MessageQueueMem"
#define SyncTwoParty_vector_name "MessageQueue"
#define SyncTwoParty_locked_vector_name "LockedMessageQueue"
        
//The fixture for SyncTwoPartyTest
class SyncTwoPartyTest : public ::testing::Test {
    public:
        std::deque<SYNC_EVENT> ev_q;
        LockedMailList* mail_queue = NULL;
        const char* test_suite_name;
        std::string test_name;
        std::string test_path;
        // Objects declared here can be used by all tests in the SyncTwoPartyTest suite.
};


int SyncTwoParty_inject_sync_event(SYNC_EVENT ev, void *management)
{
    try {
        ((SyncTwoPartyTest*)SyncTwoParty_fake_this)->ev_q.push_front(ev);
    }
    catch (exception&) {
        return 1;
    }
    return 0;
}

PEP_STATUS SyncTwoParty_message_send_callback(message* msg) {
    PEP_STATUS status = PEP_STATUS_OK;
    char* msg_str = NULL;
    mime_encode_message(msg, false, &msg_str);
    LockedMailList* lml = ((SyncTwoPartyTest*)SyncTwoParty_fake_this)->mail_queue;
    boost::posix_time::ptime end_time = boost::posix_time::second_clock::universal_time() + boost::posix_time::seconds(5);
    bool locked = lml->mutex.timed_lock(end_time);
    if (locked) {
        lml->vec.push_back(string(msg_str));
        lml->mutex.unlock();
    }    
    else 
        status = PEP_UNKNOWN_ERROR;
    free(msg_str);
    return status;
}

// threshold: max waiting time in seconds
SYNC_EVENT SyncTwoParty_retrieve_next_sync_event(void *management, unsigned threshold)
{
    SYNC_EVENT syncEvent = nullptr;
        
    time_t start, curr;
    
    start = time(NULL);
    curr = start;
    
    while (curr - start < 10) {
        if (((SyncTwoPartyTest*)SyncTwoParty_fake_this)->ev_q.empty()) {
            sleep(1);
            curr = time(NULL);
            continue;
        }
        syncEvent = ((SyncTwoPartyTest*)SyncTwoParty_fake_this)->ev_q.front();
        ((SyncTwoPartyTest*)SyncTwoParty_fake_this)->ev_q.pop_front();
        break;
    }
    
    if (!syncEvent)
        return new_sync_timeout_event();

    return syncEvent;
}

PEP_STATUS SyncTwoParty_notify_handshake(
        pEp_identity *me,
        pEp_identity *partner,
        sync_handshake_signal signal
    )
{
    return PEP_STATUS_OK;
}

TEST_F(SyncTwoPartyTest, check_sync_two_party) {
    sqlite3_initialize();
    test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();
    test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
        
    int current_message_index = 0;
    
    pid_t pid = fork();
    
    managed_shared_memory segment;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    Engine* engine;
    PEP_SESSION session;
    
    // Create process specific variables and shared mail queue
    if (pid == 0) { // child
        sleep(1);
        test_name = (test_name + "_1");
        time_t start, curr;

        start = time(NULL);
        curr = start;
        
        // Give the other process a while to set up the queue
        while (curr - start < 10) {
            // Try stuff here
            try {
                //Open the managed segment
                segment = managed_shared_memory(open_only, SyncTwoParty_segment_name);  
            }
            catch (interprocess_exception e) {    
                curr = time(NULL);
                continue;    
            }
            break;
        }   

        if ((mail_queue = (segment.find<LockedMailList>(SyncTwoParty_locked_vector_name).first)) == NULL) {
            cerr << "CHILD UNABLE TO OPEN SHARED MEMORY SEGMENT" << endl;
            exit(-1);
        }
    }
    else if (pid > 0) { // parent
        test_name = (test_name + "_0");
        
        //Remove shared memory on construction and destruction        
        struct shm_remove {
            shm_remove() { shared_memory_object::remove(SyncTwoParty_segment_name); }
            ~shm_remove(){ shared_memory_object::remove(SyncTwoParty_segment_name); }
        } remover;

        //Create a new segment with given name and size
        segment = managed_shared_memory(create_only, SyncTwoParty_segment_name, 1048576);

        //Initialize shared memory STL-compatible allocator
        const ShmemAllocator alloc_inst(segment.get_segment_manager());

        //Construct a vector named "MailList" in shared memory with argument alloc_inst
        mail_queue = segment.construct<LockedMailList>(SyncTwoParty_locked_vector_name)(alloc_inst);
    }
    else {
        // OMGWTFBBQ
        exit(-1);
    }
    
    // After this, this all happens in separate address spaces, so fake_this is safe

    SyncTwoParty_fake_this = this;
    
    // Ok, now we're on to the independent stuff. We don't have to care about which device we are here.
    test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
    cout << test_path << endl;
    
    std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

    // Get a new Engine.
    engine = new Engine(test_path);
    ASSERT_NE(engine, nullptr);

    // Ok, let's initialize test directories etc.
    engine->prep(&SyncTwoParty_message_send_callback, &SyncTwoParty_inject_sync_event, init_files);


    // Ok, try to start this bugger for this fake device
    engine->start();
    ASSERT_NE(engine->session, nullptr);
    session = engine->session;
    
    // Fake device is ready to roll.

    // Generate new identity for this device
    pEp_identity* me = new_identity("pickles@boofy.org", NULL, PEP_OWN_USERID, "Pickley Boofboof");
    status = myself(session, me);
    assert(status == PEP_STATUS_OK && me->fpr != NULL && me->fpr[0] != '\0');

    status = register_sync_callbacks(session, NULL, &SyncTwoParty_notify_handshake, &SyncTwoParty_retrieve_next_sync_event);


    // If we need to step through, then do_sync_protocol_step here in a loop.

    unsigned int last_message_index = 0;
    time_t prev_change = time(NULL);
    time_t now = prev_change;
    
    while (prev_change - now < (2 * SYNC_THRESHOLD)) {
        SYNC_EVENT event= NULL;

        bool msg_received = false;
        bool event_processed = false;
        
        boost::posix_time::ptime end_time = boost::posix_time::second_clock::universal_time() + boost::posix_time::seconds(5);
        bool locked = mail_queue->mutex.timed_lock(end_time);

        if (locked) {
            if (mail_queue->vec.size() > last_message_index) {
                message* next_msg = NULL;
                PEP_decrypt_flags_t flags = 0;
                PEP_rating rating;
                stringlist_t* keylist = NULL;
                std::string msg_str = mail_queue->vec.at(last_message_index++);
                message* actual_msg = NULL;
                mime_decode_message(msg_str.c_str(), msg_str.length(), &actual_msg);
                status = decrypt_message(session, actual_msg, &next_msg, &keylist, &rating, &flags);
                
                // FIXME: will need to be changed with sign_only
                assert(status == PEP_UNENCRYPTED || status == PEP_STATUS_OK);
                
                // If any checking of the message needs to happen, do it here.
                free_message(actual_msg);
                free_message(next_msg);
                msg_received = true;
            }
            mail_queue->mutex.unlock();
        }    
            
        event = session->retrieve_next_sync_event(session->sync_management,
                SYNC_THRESHOLD);
                
        if (event) {
            event_processed = true;
            do_sync_protocol_step(session, NULL, event);
        }    
        now = time(NULL);
        if (msg_received || event_processed)
            prev_change = now;
    } 
    
    unregister_sync_callbacks(session);
    
    if (pid > 0) {
        // Wait on dude to finish
        time_t start, curr;
        
        start = time(NULL);
        curr = start;
        
        // Give the other process time to exit
        while (curr - start < 10) {
            int status = 0;
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result > 0)
                break;
            sleep(1);    
            curr = time(NULL);    
        }   
        
        // When done, destroy the vector from the segment
        segment.destroy<LockedMailList>(SyncTwoParty_locked_vector_name);    
    }
    else {
        engine->shut_down();
        delete engine;
        engine = NULL;
        session = NULL;

        exit(0);
    }
    
    // Note: this only checks the parent processes "device", but this doesn't much matter,
    // as over time, the parent will switch roles between offerer and requester during testing 
    // due to the randomness of TIDs.
    
    // are we now grouped?
    bool is_grouped = false;
    status = deviceGrouped(session, &is_grouped);
    ASSERT_TRUE(is_grouped);
    
    // check to see if we now have two keys
    stringlist_t* keylist = NULL;    
    status = own_keys_retrieve(session, &keylist);
    ASSERT_NE(keylist, nullptr);
    ASSERT_NE(keylist->value, nullptr);
    ASSERT_NE(keylist->next, nullptr);
    ASSERT_NE(keylist->value, nullptr);    
    ASSERT_EQ(keylist->next->next, nullptr);
    free_stringlist(keylist);
    
    engine->shut_down();
    delete engine;
    engine = NULL;
    session = NULL;

}
