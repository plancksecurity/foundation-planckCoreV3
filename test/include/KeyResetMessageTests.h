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
        static constexpr const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
        
        static constexpr const char* alice_receive_reset_fpr = "6A349E4F68801E39145CD4C5712616A385412538";

        static const string alice_user_id;
        static const string bob_user_id;    
        static const string carol_user_id;
        static const string dave_user_id;
        static const string erin_user_id;
        static const string fenris_user_id;

    protected:
        void setup();
                
    private:
        void check_key_reset_message();        
        void check_reset_key_and_notify();
        void check_non_reset_receive_revoked();
        void check_reset_receive_revoked();
        void check_receive_message_to_revoked_key_from_unknown();   
        void check_receive_message_to_revoked_key_from_contact();   
        
        void send_setup();
        void receive_setup();     
        void create_msg_for_revoked_key();
        
};

#endif
