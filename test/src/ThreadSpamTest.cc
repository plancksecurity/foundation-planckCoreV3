#include <stdlib.h>
#include <string>
#include <cstring>
#include <thread>
#include <iostream>
#include <mutex>
#include <vector>

#include "pEpEngine.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"
#include "mime.h"

#include <gtest/gtest.h>

std::mutex tst_mutex;

namespace {

	//The fixture for ThreadSpamTest
    class ThreadSpamTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            ThreadSpamTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~ThreadSpamTest() override {
                // You can do clean-up work that doesn't throw exceptions here.
            }

            // If the constructor and destructor are not enough for setting up
            // and cleaning up each test, you can define the following methods:

            void SetUp() override {
                // Code here will be called immediately after the constructor (right
                // before each test).

                // Leave this empty if there are no files to copy to the home directory path
                std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

                // Get a new test Engine.
                engine = new Engine(test_path);
                ASSERT_NE(engine, nullptr);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            void TearDown() override {
                // Code here will be called immediately after each test (right
                // before the destructor).
                engine->shut_down();
                delete engine;
                engine = NULL;
                session = NULL;
            }

        private:
            const char* test_suite_name;
            const char* test_name;
            string test_path;
            // Objects declared here can be used by all tests in the ThreadSpamTest suite.

    };

}  // namespace

void tst_release(PEP_SESSION sess) {
    tst_mutex.lock();
    release(sess);
    tst_mutex.unlock();
}

void tst_run(int session_number, int num_runs) {
    PEP_SESSION my_sess;
    PEP_STATUS status = init(&my_sess, NULL, NULL);
    if (status != PEP_STATUS_OK) {
        throw string("Could not start session ") + to_string(session_number);
    }
    cout << "Ok, here in the middle of session " << session_number  << endl;
    // Do stuff here
    
    // We're lazy as Hell. We're going to set up one message and try to decrypt it again and again,.
    string msgstr = slurp("test_mails/thread_spam_test.eml");
    
    for (int i = 0; i < num_runs; i++) {
        message* enc_msg = NULL;
        message* dec_msg = NULL;
        stringlist_t* keylist = NULL;
        PEP_rating rating;
        PEP_decrypt_flags_t flags = 0;
        
        status = mime_decode_message(msgstr.c_str(), msgstr.size(), &enc_msg);
        status = decrypt_message(my_sess, enc_msg, &dec_msg, &keylist, &rating, &flags);
        if (status != PEP_STATUS_OK)
            throw string("\aSESSION ") + to_string(session_number) + ": " + tl_status_string(status);
        free_message(enc_msg);
        free_stringlist(keylist);
        free_message(dec_msg);
    }
    
    tst_release(my_sess);
}

TEST_F(ThreadSpamTest, check_thread_spam) {
    pEp_identity* carol = NULL;

    PEP_STATUS status = set_up_preset(session, CAROL,
                                      true, true, true, true, true, &carol);

    ASSERT_EQ(status , PEP_STATUS_OK);
    ASSERT_NE(carol, nullptr);
    
    int NUM_TST_THREADS = 6;
    int NUM_TST_RUNS = 200;
    
    vector<thread> workers;
    
    for (int i = 0; i < NUM_TST_THREADS; i++) {
       workers.push_back(std::thread(tst_run, i, NUM_TST_RUNS));
    }
    auto curr_thread = workers.begin();
    //Do other stuff here.
    while (curr_thread != workers.end()) {
       curr_thread->join();
       curr_thread++;
    }    
}
