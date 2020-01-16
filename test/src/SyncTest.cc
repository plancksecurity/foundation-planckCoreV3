// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <assert.h>
#include <thread>

#include "locked_queue.hh"
#include "sync_api.h"
#include "Sync_impl.h"

#include "test_util.h"

#include "pEpEngine.h"

#include "pEp_internal.h"
#include "KeySync_fsm.h"
#include "sync_codec.h"

#include "Engine.h"

#include <gtest/gtest.h>

class Sync_Adapter {
public:
    utility::locked_queue< Sync_event_t * > q;

    void processing();

    static PEP_STATUS notifyHandshake(
            pEp_identity *me,
            pEp_identity *partner,
            sync_handshake_signal signal
        );
    static int inject_sync_event(SYNC_EVENT ev, void *management);
    static Sync_event_t *retrieve_next_sync_event(void *management, unsigned threshold);
    static PEP_STATUS messageToSend(struct _message *msg);

    static void sync_thread(PEP_SESSION session, Sync_Adapter *adapter);
};


void Sync_Adapter::processing()
{
    output_stream << "waiting for processing\n";
    const struct timespec arr[] = {{0, 100000000L}};
    while (!q.empty()) {
        nanosleep(arr, NULL);
    }
}

PEP_STATUS Sync_Adapter::notifyHandshake(
        pEp_identity *me,
        pEp_identity *partner,
        sync_handshake_signal signal
    )
{
    return PEP_STATUS_OK;
}

int Sync_Adapter::inject_sync_event(SYNC_EVENT ev, void *management)
{
    Sync_event_t *_ev = ev;
    switch (_ev->fsm) {
        case Sync_PR_keysync:
            output_stream << "injecting event " << KeySync_event_name(_ev->event) << "\n";
            break;
        default:
            output_stream << "unknown state machine: " << _ev->fsm << "\n";
            assert(0);
    }
    auto adapter = static_cast< Sync_Adapter *>(management);
    adapter->q.push_front(ev);
    return 0;
}

Sync_event_t *Sync_Adapter::retrieve_next_sync_event(void *management, unsigned threshold)
{
    auto adapter = static_cast< Sync_Adapter *>(management);
    time_t started = time(nullptr);
    bool timeout = false;

    while (adapter->q.empty()) {
        int i = 0;
        ++i;
        if (i > 10) {
            if (time(nullptr) > started + threshold) {
                timeout = true;
                break;
            }
            i = 0;
        }
        const struct timespec arr[] = {{0, 100000000L}};        
        nanosleep(arr, NULL);
    }

    if (timeout)
        return SYNC_TIMEOUT_EVENT;

    Sync_event_t *ev = adapter->q.pop_front();
    if (ev) {
        switch (ev->fsm) {
            case Sync_PR_keysync:
                output_stream << "sync thread: retrieving event " << KeySync_event_name(ev->event) << "\n";
                break;
            default:
                output_stream << "sync thread: unknown state machine: " << ev->fsm << "\n";
                assert(0);
        }
    }
    else {
        output_stream << "sync thread: retrieving shutdown\n";
    }

    return ev;
}

PEP_STATUS Sync_Adapter::messageToSend(struct _message *msg)
{
    assert(msg && msg->attachments);

    output_stream << "sending message:\n";

    for (bloblist_t *b = msg->attachments; b && b->value; b = b->next) {
        if (b->mime_type && strcasecmp(b->mime_type, "application/pEp.sync") == 0) {
            assert(msg->from && msg->from->address && msg->from->username);
            output_stream << "<!-- " << msg->from->username << " <" << msg->from->address << "> -->\n";
            char *text = NULL;
            PEP_STATUS status = PER_to_XER_Sync_msg(msg->attachments->value, msg->attachments->size, &text);
            assert(status == PEP_STATUS_OK);
            output_stream << text << "\n";
            free(text);
        }
    }

    free_message(msg);
    return PEP_STATUS_OK;
}

void Sync_Adapter::sync_thread(PEP_SESSION session, Sync_Adapter *adapter)
{
    output_stream << "sync_thread: startup\n";
    do_sync_protocol(session, adapter);
    output_stream << "sync_thread: shutdown\n";
}


namespace {

	//The fixture for SyncTest
    class SyncTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

            Sync_Adapter adapter;
            PEP_SESSION sync = NULL;
            thread *sync_thread;
            

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            SyncTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~SyncTest() override {
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
                engine->prep(NULL, NULL, init_files);

                // Ok, try to start this bugger. Is this totally irrelevant for this case??
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'

                pEp_identity *self = new_identity("alice@synctests.pEp", nullptr, "23", "Alice Miller");
                assert(self);
                output_stream << "setting own identity for " << self->address << "\n";
                PEP_STATUS status = myself(session, self);
                assert(self->me);
                assert(self->fpr);
                output_stream << "fpr: " << self->fpr << "\n";
                free_identity(self);

                status = init(&sync, Sync_Adapter::messageToSend, Sync_Adapter::inject_sync_event);
                if (status != PEP_STATUS_OK)
                    throw std::runtime_error((string("init returned ") + tl_status_string(status)).c_str());

                output_stream << "initialize sync and start first state machine\n";
                status = register_sync_callbacks(
                    sync,
                    (void *) &adapter.q,
                    Sync_Adapter::notifyHandshake,
                    Sync_Adapter::retrieve_next_sync_event
                );
                if (status != PEP_STATUS_OK)
                    throw std::runtime_error((string("register sync status returned ") + tl_status_string(status)).c_str());
                if (sync->sync_state.keysync.state != Sole)
                    throw std::runtime_error((string("keysync.state was supposed to be ") + to_string((int)Sole) + " but was " + to_string((int)(sync->sync_state.keysync.state))).c_str());

                output_stream << "creating thread for sync\n";
                sync_thread = new thread(Sync_Adapter::sync_thread, sync, &adapter);

            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                
                adapter.processing();

                output_stream << "sending shutdown to sync thread\n";
                adapter.q.push_front(nullptr);
                sync_thread->join();

                unregister_sync_callbacks(sync);
                release(sync);
                
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the SyncTest suite.

    };

}  // namespace

TEST_F(SyncTest, check_sync)
{
    output_stream << "check_sync(): trigger KeyGen event\n";
    signal_Sync_event(sync, Sync_PR_keysync, KeyGen, NULL);
    adapter.processing();

    output_stream << "check_sync(): cry for unknown key\n";
    signal_Sync_event(sync, Sync_PR_keysync, CannotDecrypt, NULL);
}
