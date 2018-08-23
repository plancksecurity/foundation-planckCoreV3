// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <thread>

#include "pEpEngine.h"
#include "sync_api.h"

#include "pEp_internal.h"
#include "KeySync_fsm.h"
#include "Sync_codec.h"

#include "EngineTestSessionSuite.h"
#include "SyncTests.h"

#include "locked_queue.hh"

using namespace std;

class Sync_Adapter {
public:
    utility::locked_queue< Sync_event_t * > q;

    static PEP_STATUS notifyHandshake(
            void *obj,
            pEp_identity *me,
            pEp_identity *partner,
            sync_handshake_signal signal
        )
    {
        return PEP_STATUS_OK;
    }

    static int inject_sync_event(SYNC_EVENT ev, void *management)
    {
        Sync_event_t *_ev = ev;
        cout << "injecting event " << _ev->event << "\n";
        auto adapter = static_cast< Sync_Adapter *>(management);
        adapter->q.push_front(ev);
        return 0;
    }

    static Sync_event_t *retrieve_next_sync_event(void *management)
    {
        auto adapter = static_cast< Sync_Adapter *>(management);
        while (adapter->q.empty()) {
            sleep(1);
        }
        Sync_event_t *result = adapter->q.pop_front();
        if (result)
            cout << "retrieving sync event\n";
        else
            cout << "retrieving shutdown\n";
        return result;
    }

    static PEP_STATUS messageToSend(void *obj, struct _message *msg)
    {
        assert(msg && msg->attachments);
        
        cout << "sending message:\n";

        for (bloblist_t *b = msg->attachments; b && b->value; b = b->next) {
            if (b->mime_type && strcasecmp(b->mime_type, "application/pEp.sync") == 0) {
                char *text = NULL;
                PEP_STATUS status = PER_to_XER_Sync_msg(msg->attachments->value, msg->attachments->size, &text);
                assert(status == PEP_STATUS_OK);
                cout << text << "\n";
                free(text);
            }
        }

        free_message(msg);
        return PEP_STATUS_OK;
    }

    static void sync_thread(PEP_SESSION session, Sync_Adapter *adapter)
    {
        cout << "sync_thread: startup\n";
        do_sync_protocol(session, adapter);
        cout << "sync_thread: shutdown\n";
    }
};

SyncTests::SyncTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SyncTests::check_sync"),
                                                                      static_cast<Func>(&SyncTests::check_sync)));
}

void SyncTests::check_sync()
{
    Sync_Adapter adapter;
    PEP_SESSION sync = NULL;
    thread *sync_thread;
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity *self = new_identity("alice@synctests.pEp", nullptr, "23", "Alice Miller");
    assert(self);
    cout << "setting own identity for " << self->address << "\n";
    status = myself(session, self);
    assert(self->me);
    assert(self->fpr);
    cout << "fpr: " << self->fpr << "\n";
    free_identity(self);

    status = init(&sync, Sync_Adapter::messageToSend, Sync_Adapter::inject_sync_event);
    TEST_ASSERT(status == PEP_STATUS_OK);

    cout << "initialize sync and start first state machine\n";
    status = register_sync_callbacks(
            sync,
            &adapter.q,
            Sync_Adapter::notifyHandshake,
            Sync_Adapter::retrieve_next_sync_event
        );
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(sync->sync_state.keysync.state == Sole);

    cout << "creating thread for sync\n";
    sync_thread = new thread(Sync_Adapter::sync_thread, sync, &adapter);
 
    cout << "sending shutdown to sync thread\n";
    adapter.q.push_front(nullptr);
    sync_thread->join();

    unregister_sync_callbacks(sync);
    release(sync);
}

