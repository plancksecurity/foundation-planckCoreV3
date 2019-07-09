// This file is under GNU General Public License 3.0
// see LICENSE.txt

#ifndef STRNSTR_H
#define STRNSTR_H

#include <string>
#include "EngineTestIndividualSuite.h"

using namespace std;

class StrnstrTests : public EngineTestIndividualSuite {
    public:
        StrnstrTests(string test_suite, string test_home_dir);
    private:
        void check_strnstr_equal();
        void check_strnstr_first_null();
        void check_strnstr_second_null();
        void check_strnstr_both_null();
        void check_strnstr_first_empty();
        void check_strnstr_second_empty();
        void check_strnstr_both_empty();
        void check_strnstr_first_letter_only();
        void check_strnstr_first_two_only();
        void check_strnstr_all_but_last();
        void check_strnstr_same_len_all_but_last();
        void check_strnstr_same_len_none();
        void check_strnstr_same_big_smaller();
        void check_strnstr_shift_one_no_match();
        void check_strnstr_shift_to_end();
        void check_strnstr_match_after_end();
        void check_strnstr_equal_but_size_too_small();
};

#endif
