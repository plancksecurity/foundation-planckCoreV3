// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef SUBKEY_RATING_EVAL_H
#define SUBKEY_RATING_EVAL_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class SubkeyRatingEvalTests : public EngineTestIndividualSuite {
    public:
        SubkeyRatingEvalTests(string test_suite, string test_home_dir);
    private:
        void check_subkey_rating_eval();
        void check_subkey_rating_eval_no_es();
        void check_subkey_rating_eval_weak_s();    
        void check_subkey_rating_eval_ecc_s();
        void check_subkey_rating_eval_weak_e_strong_ecc_se();
        void check_subkey_rating_eval_bad_es();
        void check_subkey_rating_eval_bad_e();
        void check_subkey_rating_eval_bad_s_ecc_e();    
        void check_subkey_rating_eval_revoked_sign_no_alt();    
        void check_subkey_rating_eval_revoked_e_with_alt();            

};

#endif
