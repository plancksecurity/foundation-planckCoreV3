// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_TEST_STATIC_H
#define PEP_TEST_STATIC_H

#include <string>

using namespace std;

class pEpTestStatic {
    public:
        static size_t getMaxPathSize();
        static size_t sun_path_size;
        static size_t getAvailablePathChars(string keypath_str);
        static size_t available_path_chars;
        static const size_t classname_chars;
        static const size_t testnum_path_chars;
        static const size_t max_test_num;

    private:
        pEpTestStatic() {};
};

#endif
