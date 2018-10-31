
#ifndef PEP_TEST_OUTPUT_H
#define PEP_TEST_OUTPUT_H

#include <cpptest.h>
#include <vector>
#include <string>

namespace Test {
    class pEpTestOutput : public Output {
        public:
            pEpTestOutput();
            ~pEpTestOutput() {};
            void finished(int tests, const Time& time);
            void initialize(int tests) {};
            void suite_start(int tests, const std::string& name);
            void suite_end(int tests, const std::string& name,
                           const Time& time);
            void test_start(const std::string& name);
            void test_end(const std::string& name, bool ok,
                          const Time& time);
            void assertment(const Test::Source& s);
            
            void outputCorrectPercentage(int num_tests, int failures, int width);
            
        private:
            static constexpr const char* huge_sepline = "///////////////////////////////////////////////////////////////////////////\n";
            static constexpr const char* alt_sepline = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
            static constexpr const char* big_sepline = "********************************************************\n";
            static constexpr const char* med_sepline = "-----------------------------------\n";
            static constexpr const char* sml_sepline = "++++++++++++++++++++++++++\n";
            static constexpr const char* lil_sepline = "~~~~~~\n";
            int _total_failed;
            int _total_tests;
            int _suite_failed;
            int _suite_total;
            std::string _suite_name;
            std::string _test_name;
            std::vector<Source> _test_errors;
            
    };
}
#endif