#ifndef ENGINE_TEST_SUITE_H
#define ENGINE_TEST_SUITE_H

#include <cpptest.h>
#include <string>
#include <vector>
#include "pEpEngine.h"

using namespace std;

class EngineTestSuite : public Test::Suite {
    public:
        EngineTestSuite(string suitename, string test_home_dir);
        virtual ~EngineTestSuite();
        
        void add_test_to_suite(void (*test)()); // We do this so we can count
                
    protected:
        PEP_SESSION session;
        string test_home;
        string prev_gpg_home;
        string name;
        
        string current_test_name;
        
        unsigned int number_of_tests;
        unsigned int on_test_number;
        
        virtual void setup();
        virtual void tear_down();
        void set_full_env();
        void restore_full_env();
        void initialise_test_home();
        
};
#endif
