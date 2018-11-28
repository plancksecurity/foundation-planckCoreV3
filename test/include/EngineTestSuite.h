#ifndef ENGINE_TEST_SUITE_H
#define ENGINE_TEST_SUITE_H

#include <cpptest.h>
#include <string>
#include <map>
#include <vector>
#include <utility>
#include "pEpEngine.h"

using namespace std;

class EngineTestSuite : public Test::Suite {
    public:
        EngineTestSuite(string suitename, string test_home_dir);
        virtual ~EngineTestSuite();
        
        void add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()> test_func);
        void output_test_header(const char* test_name);
        void output_test_footer(const char* test_name);

    protected:
        PEP_SESSION session;
        string test_home;
        string real_home;
        string prev_pgp_home;
        string name;
        
        string current_test_name;

        messageToSend_t cached_messageToSend;
        inject_sync_event_t cached_inject_sync_event;

#define TEST_FAILED_MESSAGE_BUFSIZE 1000        
        char failed_msg_buf[TEST_FAILED_MESSAGE_BUFSIZE];
        
        std::map<std::string, void (Test::Suite::*)()> test_map;                
        
        string my_name;
        
        unsigned int number_of_tests;
        unsigned int on_test_number;
        
        string temp_test_home;
        
        virtual void setup();
        virtual void tear_down();
        
        void set_full_env();
        void set_full_env(const char* gpg_conf_copy_path, const char* gpg_agent_conf_file_copy_path, const char* db_conf_file_copy_path);
        void restore_full_env();
        void initialise_test_home();
        void set_my_name();    
	
        void copy_conf_file_to_test_dir(const char* dest_path, const char* conf_orig_path, const char* conf_dest_name);
        
        std::vector<std::pair<std::string, std::string>> gpgdir_fileadd_queue;
        std::vector<std::pair<std::string, std::string>> homedir_fileadd_queue;
        void add_file_to_gpg_dir_queue(std::string copy_from, std::string dst_fname);    
        void add_file_to_home_dir_queue(std::string copy_from, std::string dst_fname);
        void process_file_queue(std::string dirname, std::vector<std::pair<std::string, std::string>> file_queue);

};
#endif
