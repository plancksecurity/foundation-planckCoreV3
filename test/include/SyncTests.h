// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SYNC_H
#define SYNC_H

#include <string>
#include <thread>
#include "EngineTestSessionSuite.h"
#include "locked_queue.hh"
#include "sync_api.h"
#include "Sync_impl.h"

using namespace std;

class Sync_Adapter {
public:
    utility::locked_queue< Sync_event_t * > q;

    void processing();

    static PEP_STATUS notifyHandshake(
            void *obj,
            pEp_identity *me,
            pEp_identity *partner,
            sync_handshake_signal signal
        );
    static int inject_sync_event(SYNC_EVENT ev, void *management);
    static Sync_event_t *retrieve_next_sync_event(void *management);
    static PEP_STATUS messageToSend(void *obj, struct _message *msg);

    static void sync_thread(PEP_SESSION session, Sync_Adapter *adapter);
};

class SyncTests : public EngineTestSessionSuite {
    public:
        SyncTests(string test_suite, string test_home_dir);

        void setup();
        void tear_down();

    private:
        Sync_Adapter adapter;
        PEP_SESSION sync = NULL;
        thread *sync_thread;

        void check_sync();
};

#endif
