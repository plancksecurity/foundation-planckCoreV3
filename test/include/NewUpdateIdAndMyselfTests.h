// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef NEW_UPDATE_ID_AND_MYSELF_H
#define NEW_UPDATE_ID_AND_MYSELF_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class NewUpdateIdAndMyselfTests : public EngineTestSessionSuite {
    public:
        NewUpdateIdAndMyselfTests(string test_suite, string test_home_dir);
	protected:
		char* uniqname;
		char* own_user_id;
		char* start_username;
		char* generated_fpr;
		char* default_own_id;
		char* alias_id;
        char* new_fpr;
        const char* alex_address;
        const char* alex_fpr;
        const char* alex_userid;
        const char* alex_username;
        const char* new_username;
    
        void setup();
        void tear_down();
    private:
        void myself_no_record_no_input_fpr();
        void myself_no_input_fpr_w_record();
        void myself_no_input_fpr_diff_user_id_w_record();
        void myself_replace_fpr();
        void myself_replace_fpr_revoke_key();
        void update_identity_w_matching_address_user_id_username();
        void update_identity_w_matching_address_user_id_new_username();
        void update_identity_w_matching_address_user_id_only();
        void update_identity_use_address_username_only();
        void update_identity_use_address_only();
        void update_identity_use_address_only_on_own_ident();
        void update_identity_non_existent_user_id_address();
        void update_identity_address_username_userid_no_record();
        void update_identity_address_username_no_record();
        void update_identity_address_only_multiple_records();
        void key_elect_expired_key();
        void key_elect_only_revoked_mistrusted();
};

#endif
