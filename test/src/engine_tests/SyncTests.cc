// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"
#include "sync_api.h"

#include "pEp_internal.h"
#include "KeySync_fsm.h"

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
        auto adapter = static_cast< Sync_Adapter *>(management);
        adapter->q.push_front(ev);
        return 0;
    }

    static Sync_event_t *retrieve_next_sync_event(void *management)
    {
        auto adapter = static_cast< Sync_Adapter *>(management);
        return adapter->q.pop_front();
    }

    static PEP_STATUS messageToSend(void *obj, struct _message *msg)
    {
        assert(msg);
        return PEP_STATUS_OK;
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

    PEP_STATUS status = init(&sync, Sync_Adapter::messageToSend);
    TEST_ASSERT(status == PEP_STATUS_OK);

    status = register_sync_callbacks(
            sync,
            &adapter.q,
            Sync_Adapter::notifyHandshake,
            Sync_Adapter::inject_sync_event,
            Sync_Adapter::retrieve_next_sync_event
        );
    TEST_ASSERT(status == PEP_STATUS_OK);

    TEST_ASSERT(sync->sync_state.keysync.state == Sole);

    unregister_sync_callbacks(sync);
    release(sync);
}

