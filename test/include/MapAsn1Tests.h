// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MAP_ASN1_H
#define MAP_ASN1_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class MapAsn1Tests : public EngineTestSessionSuite {
    public:
        MapAsn1Tests(string test_suite, string test_home_dir);
    private:
        void check_map_asn1();
};

#endif
