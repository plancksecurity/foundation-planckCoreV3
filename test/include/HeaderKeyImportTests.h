// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef HEADER_KEY_IMPORT_H
#define HEADER_KEY_IMPORT_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class HeaderKeyImportTests : public EngineTestIndividualSuite {
    public:
        HeaderKeyImportTests(string test_suite, string test_home_dir);
    private:
        void check_header_key_import();
        void base_64_minimal_round();
        void base_64_minimal_padded();
        void base_64_minimal_unpadded();
        void base_64_minimal_leading_whitespace_round();
        void base_64_minimal_leading_whitespace_padded();
        void base_64_minimal_leading_whitespace_unpadded();
        void base_64_minimal_trailing_whitespace_round();
        void base_64_minimal_trailing_whitespace_padded();
        void base_64_minimal_trailing_whitespace_unpadded();
        void base_64_minimal_internal_whitespace_round();
        void base_64_minimal_internal_whitespace_padded();
        void base_64_minimal_internal_whitespace_unpadded();
        void base_64_round();
        void base_64_padded();
        void base_64_unpadded();
        void base_64_leading_whitespace_round();
        void base_64_leading_whitespace_padded();
        void base_64_leading_whitespace_unpadded();
        void base_64_trailing_whitespace_round();
        void base_64_trailing_whitespace_padded();
        void base_64_trailing_whitespace_unpadded();
        void base_64_kitchen_sink_round();
        void base_64_kitchen_sink_padded();
        void base_64_kitchen_sink_unpadded();
};

#endif
