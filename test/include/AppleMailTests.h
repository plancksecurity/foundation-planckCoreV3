// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef APPLE_MAIL_TESTS_H
#define APPLE_MAIL_TESTS_H

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

class AppleMailTests : public EngineTestIndividualSuite {
    public:
        AppleMailTests(string suitename, string test_home_dir);
    private:
        void check_apple_mail();
};

#endif
