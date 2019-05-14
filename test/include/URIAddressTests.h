// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef U_R_I_ADDRESS_H
#define U_R_I_ADDRESS_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class URIAddressTests : public EngineTestIndividualSuite {
    public:
        URIAddressTests(string test_suite, string test_home_dir);
    private:
        void check_uri_address_genkey();
        void check_uri_address_encrypt();        
};

#endif
