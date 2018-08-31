// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef KEY_RESET_MESSAGE_H
#define KEY_RESET_MESSAGE_H

#include <string>
#include "EngineTestIndividualSuite.h"
#include "sync.h"
#include "pEpEngine.h"

using namespace std;

class KeyResetMessageTests : public EngineTestIndividualSuite {
    public:
        KeyResetMessageTests(string test_suite, string test_home_dir);
        
        static PEP_STATUS message_send_callback(void *obj, message *msg);
        
        vector<message*> m_queue;
        
        static constexpr const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";

    protected:
        void setup();
                
    private:
        void check_key_reset_message();        
        void check_reset_key_and_notify();
        void check_receive_revoked();
        void check_receive_key_reset_private();
        void check_receive_key_reset_wrong_signer();
        void check_receive_key_reset_unsigned();
        void check_receive_message_to_revoked_key();   
        
        void send_setup();
        void receive_setup();     
};

#endif
