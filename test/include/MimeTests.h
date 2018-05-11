// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef MIME_H
#define MIME_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class MimeTests : public EngineTestSessionSuite {
    public:
        MimeTests(string test_suite, string test_home_dir);
    private:
        void check_mime();
};

#endif
