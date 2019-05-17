// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef DELETE_KEY_H
#define DELETE_KEY_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class DeleteKeyTests : public EngineTestIndividualSuite {
    public:
        DeleteKeyTests(string test_suite, string test_home_dir);

        static constexpr const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
        static constexpr const char* bob_fpr = "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39";
        static constexpr const char* carol_fpr = "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42";
        static constexpr const char* dave_fpr = "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6";
        static constexpr const char* erin_fpr = "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA";
        static constexpr const char* fenris_fpr = "0969FA229DF21C832A64A04711B1B9804F3D2900";

        static const string alice_user_id;
        static const string bob_user_id;    
        static const string carol_user_id;
        static const string dave_user_id;
        static const string erin_user_id;
        static const string fenris_user_id;

    private:
        void import_test_keys();
        
        void check_delete_single_pubkey();
        void check_delete_pub_priv_keypair();
        void check_delete_multiple_keys();
        void check_delete_all_keys();
        void check_delete_key_not_found();
        void check_delete_empty_keyring();        
};

#endif
