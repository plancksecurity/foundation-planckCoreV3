#include <stdlib.h>
#include <sys/un.h>

#include "pEpTestStatic.h"
#include <math.h>
#include <string>
#include "TestConstants.h"

using namespace std;

size_t pEpTestStatic::sun_path_size = 0;
size_t pEpTestStatic::available_path_chars = 0;

const size_t pEpTestStatic::classname_chars = 6;
const size_t pEpTestStatic::testnum_path_chars = 4;
const size_t pEpTestStatic::max_test_num = pow(10, pEpTestStatic::testnum_path_chars) - 1;

size_t pEpTestStatic::getMaxPathSize() {
    if (pEpTestStatic::sun_path_size == 0) {
        struct sockaddr_un s;
        pEpTestStatic::sun_path_size = sizeof(s.sun_path);
    }
    return pEpTestStatic::sun_path_size;
}

size_t pEpTestStatic::getAvailablePathChars(string keypath_str) {
    if (pEpTestStatic::available_path_chars == 0) {
        available_path_chars = pEpTestStatic::getMaxPathSize() - classname_chars - testnum_path_chars - keypath_str.size() - 4; // slashes
    }
    return pEpTestStatic::available_path_chars;
}
