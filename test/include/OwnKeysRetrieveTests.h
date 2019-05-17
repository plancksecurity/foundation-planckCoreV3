// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef OWN_KEYS_RETRIEVE_H
#define OWN_KEYS_RETRIEVE_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class OwnKeysRetrieveTests : public EngineTestIndividualSuite {
    public:
        OwnKeysRetrieveTests(string test_suite, string test_home_dir);
    private:
        void check_own_keys_retrieve_single_private();
        void check_own_keys_retrieve_single_private_single_pub();
        void check_own_keys_retrieve_multiple_private();
        void check_own_keys_retrieve_multiple_private_and_pub();
        void check_own_keys_retrieve_multi_pub_only();
        void check_own_keys_retrieve_no_own();
        void check_own_keys_retrieve_multi_idents_one_key();
        void check_own_keys_retrieve_multi_idents_one_priv_key_multi_pub();
};
#endif
