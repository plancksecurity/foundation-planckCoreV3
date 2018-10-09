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
        void base_64_minimal_round();
        void base_64_minimal_padded_1();
        void base_64_minimal_padded_2();
        void base_64_minimal_unpadded_1();
        void base_64_minimal_unpadded_2();    
        void base_64_minimal_leading_whitespace_round();
        void base_64_minimal_leading_whitespace_padded_1();
        void base_64_minimal_leading_whitespace_padded_2();
        void base_64_minimal_leading_whitespace_unpadded_1();        
        void base_64_minimal_leading_whitespace_unpadded_2();
        void base_64_minimal_trailing_whitespace_round();
        void base_64_minimal_trailing_whitespace_padded_1();
        void base_64_minimal_trailing_whitespace_padded_2();
        void base_64_minimal_trailing_whitespace_unpadded_1();        
        void base_64_minimal_trailing_whitespace_unpadded_2();
        void base_64_minimal_internal_whitespace_round();
        void base_64_minimal_internal_whitespace_padded_1();
        void base_64_minimal_internal_whitespace_padded_2();
        void base_64_minimal_internal_whitespace_unpadded_1();        
        void base_64_minimal_internal_whitespace_unpadded_2();
        void base_64_round();
        void base_64_padded_1();
        void base_64_padded_2();
        void base_64_unpadded_1();        
        void base_64_unpadded_2();
        void base_64_leading_whitespace_round();
        void base_64_leading_whitespace_padded_1();
        void base_64_leading_whitespace_padded_2();
        void base_64_leading_whitespace_unpadded_1();        
        void base_64_leading_whitespace_unpadded_2();
        void base_64_trailing_whitespace_round();
        void base_64_trailing_whitespace_padded_1();
        void base_64_trailing_whitespace_padded_2();
        void base_64_trailing_whitespace_unpadded_1();        
        void base_64_trailing_whitespace_unpadded_2();
        void base_64_kitchen_sink_round();
        void base_64_kitchen_sink_padded_1();
        void base_64_kitchen_sink_padded_2();
        void base_64_kitchen_sink_unpadded_1();        
        void base_64_kitchen_sink_unpadded_2();
        
        bool verify_base_64_test(const char* input, const char* desired_output);
};

#endif
