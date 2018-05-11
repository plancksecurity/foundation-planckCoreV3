// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef PEP_SUBJECT_RECEIVED_H
#define PEP_SUBJECT_RECEIVED_H

#include <string>
#include "EngineTestSessionSuite.h"

using namespace std;

class PepSubjectReceivedTests : public EngineTestSessionSuite {
    public:
        PepSubjectReceivedTests(string test_suite, string test_home_dir);
    private:
        void check_pep_subject_received();
};

#endif
