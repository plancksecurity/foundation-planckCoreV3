#ifndef DECORATE_TESTS_H
#define DECORATE_TESTS_H
// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cpptest.h>
#include <cpptest-suite.h>
#include <cpptest-textoutput.h>
#include "mime.h"
#include "message_api.h"
#include "test_util.h"

using namespace std;

class DecorateTests : public EngineTestSessionSuite {
    public:
        DecorateTests(string suitename, string test_home_dir);
    private:
        void check_decorate();
};

#endif
