// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef BLOBLIST_TESTS_H
#define BLOBLIST_TESTS_H

#include <string>
#include "EngineTestSuite.h"

using namespace std;

class BloblistTests : public EngineTestSuite {
    public:
        BloblistTests(string suitename, string test_home_dir);
    private:
        void check_bloblists();
        bool test_blob_equals(size_t size1, char* blob1, size_t size2, char* blob2);
        bool test_bloblist_node_equals(bloblist_t* val1, bloblist_t* val2);
};

#endif
