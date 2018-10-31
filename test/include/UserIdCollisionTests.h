// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef USER_ID_COLLISION_H
#define USER_ID_COLLISION_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class UserIdCollisionTests : public EngineTestIndividualSuite {
    public:
        UserIdCollisionTests(string test_suite, string test_home_dir);
    
    protected:
        void setup();
        void tear_down();
        
        // own user
        pEp_identity* user_alice;
        // real ID, only minimal info w/ username
        pEp_identity* real_alex;
        // tofu ID, only minimal info w/ username        
        pEp_identity* tofu_alex;
        // real ID, only minimal info w/o username
        pEp_identity* real_alex_0;
        // tofu ID, only minimal info w/o username
        pEp_identity* tofu_alex_0;
        // real ID, only minimal info w/o username
        pEp_identity* real_alex_1;
        // tofu ID, only minimal info w/o username
        pEp_identity* tofu_alex_1;
        // real ID, various kinds of info
        pEp_identity* real_alex_2;
        // tofu ID, various kinds of info
        pEp_identity* tofu_alex_2;
        // real ID, various kinds of info
        pEp_identity* real_alex_3;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_3;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_4;
        // real ID, various kinds of info
        pEp_identity* real_alex_4;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_5;
        // real ID, various kinds of info
        pEp_identity* real_alex_5;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_6a;
        // real ID, various kinds of info
        pEp_identity* real_alex_6a;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_6b;
        // real ID, various kinds of info
        pEp_identity* real_alex_6b;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_6c;
        // real ID, various kinds of info
        pEp_identity* real_alex_6c;
        // tofu ID, various kinds of info        
        pEp_identity* tofu_alex_6d;
        // real ID, various kinds of info
        pEp_identity* real_alex_6d;
        
        const char* const alice_keyfile = "test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc";
        const char* const alice_keyid = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
        const char* const alice_email = "pep.test.alice@pep-project.org";
        const char* const alex_keyfile = "test_keys/pub/pep.test.alexander-0x26B54E4E_pub.asc";
        const char* const alex_keyid = "3AD9F60FAEB22675DB873A1362D6981326B54E4E";        
        const char* const alex_email = "pep.test.alexander@peptest.ch";        
        const char* const alex0_keyfile = "test_keys/pub/pep.test.alexander0-0x3B7302DB_pub.asc";
        const char* const alex0_keyid = "F4598A17D4690EB3B5B0F6A344F04E963B7302DB";
        const char* const alex0_email = "pep.test.alexander0@darthmama.org";                
        const char* const alex1_keyfile = "test_keys/pub/pep.test.alexander1-0x541260F6_pub.asc";
        const char* const alex1_keyid = "59AF4C51492283522F6904531C09730A541260F6";        
        const char* const alex1_email = "pep.test.alexander1@darthmama.org";                                
        const char* const alex2_keyfile = "test_keys/pub/pep.test.alexander2-0xA6512F30_pub.asc";
        const char* const alex2_keyid = "46A994F19077C05610870273C4B8AB0BA6512F30";
        const char* const alex2_email = "pep.test.alexander2@darthmama.org";                                
        const char* const alex3_keyfile = "test_keys/pub/pep.test.alexander3-0x724B3975_pub.asc";
        const char* const alex3_keyid = "5F7076BBD92E14EA49F0DF7C2CE49419724B3975";        
        const char* const alex3_email = "pep.test.alexander3@darthmama.org";                
        const char* const alex4_keyfile = "test_keys/pub/pep.test.alexander4-0x844B9DCF_pub.asc";
        const char* const alex4_keyid = "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF";        
        const char* const alex4_email = "pep.test.alexander4@darthmama.org";                
        const char* const alex5_keyfile = "test_keys/pub/pep.test.alexander5-0x0773CD29_pub.asc";
        const char* const alex5_keyid = "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29";        
        const char* const alex5_email = "pep.test.alexander5@darthmama.org";                
        const char* const alex6a_keyfile = "test_keys/pub/pep.test.alexander6-0xBDA17020_pub.asc";
        const char* const alex6a_keyid = "B4CE2F6947B6947C500F0687AEFDE530BDA17020";        
        const char* const alex6_email = "pep.test.alexander6@darthmama.org";                
        const char* const alex6b_keyfile = "test_keys/pub/pep.test.alexander6-0x503B14D8_pub.asc";
        const char* const alex6b_keyid = "2E21325D202A44BFD9C607FCF095B202503B14D8";        
        const char* const alex6c_keyfile = "test_keys/pub/pep.test.alexander6-0xA216E95A_pub.asc";
        const char* const alex6c_keyid = "3C1E713D8519D7F907E3142D179EAA24A216E95A";        
        const char* const alex6d_keyfile = "test_keys/pub/pep.test.alexander6-0x0019697D_pub.asc";
        const char* const alex6d_keyid = "74D79B4496E289BD8A71B70BA8E2C4530019697D";        
        
    private:
        void simple_tofu_collision();        
        void simple_tofu_collision_different_usernames();
        void tofu_collision_two_tofus();        
        void tofu_collision_two_tofus_diff_usernames();
        void real_followed_by_explicit_tofu();
        void merge_records_normal();
        void merge_records_set();
        void merge_records_set_2();
};

#endif
