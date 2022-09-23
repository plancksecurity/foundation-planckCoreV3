// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <assert.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "message_api.h"
#include "media_key.h"
#include "TestConstants.h"

#include "TestUtilities.h"

#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for MediaKeyTest
    class MediaKeyTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            MediaKeyTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~MediaKeyTest() override {
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
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NE(engine->session, nullptr);
                session = engine->session;

                // Engine is up. Keep on truckin'
                
                string keystr = slurp("test_keys/priv/bcc_test_dude_0-0x1CCCFC41_priv.asc");
                PEP_STATUS status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);    
                pEp_identity * me = new_identity("bcc_test_dude_0@pep.foundation", "0AE9AA3E320595CF93296BDFA155AC491CCCFC41", PEP_OWN_USERID, "BCC Test Sender");
                status = set_own_key(session, me, "0AE9AA3E320595CF93296BDFA155AC491CCCFC41");
                keystr = slurp("test_keys/pub/bcc_test_dude_0-0x1CCCFC41_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                keystr = slurp("test_keys/pub/bcc_test_dude_1-0xDAC746BE_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);
                keystr = slurp("test_keys/pub/bcc_test_dude_2-0x53CECCF7_pub.asc");
                status = import_key(session, keystr.c_str(), keystr.size(), NULL);
                ASSERT_TRUE(status == PEP_TEST_KEY_IMPORT_SUCCESS);    

                free_identity(me);
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
            // Objects declared here can be used by all tests in the MediaKeyTest suite.

    };

}  // namespace

TEST_F(MediaKeyTest, check_lookup) {
    PEP_STATUS status = PEP_UNKNOWN_ERROR;

#define TEST_KEY(ADDRESS, EXPECTED_KEY)                                     \
    do {                                                                    \
        const char *_address = (ADDRESS);                                   \
        const char *_expected_fpr = (EXPECTED_KEY);                         \
        char *_fpr = NULL;                                                  \
        fprintf(stderr, "Searching for %s , expecting %s ...\n",            \
                _address, (_expected_fpr ? _expected_fpr : "(no key)"));    \
        PEP_STATUS _status = media_key_lookup_address(session, _address,    \
                                                      &_fpr);               \
        if (_status != PEP_STATUS_OK && _status != PEP_KEY_NOT_FOUND)       \
            ASSERT_EQ(true, false);                                         \
        else                                                                \
            fprintf(stderr, "...found %s\n", (_fpr ? _fpr : "(no key)"));   \
        if (_expected_fpr == NULL)                                          \
            ASSERT_EQ(_fpr, nullptr);                                       \
        else {                                                              \
            ASSERT_NE(_fpr, nullptr);                                       \
            ASSERT_EQ(strcmp(_fpr, _expected_fpr), 0);                      \
        }                                                                   \
        free(_fpr);                                                         \
        fprintf(stderr, "\n");                                              \
    } while (false)

    /* Here instead of using actual key FPR we use human-readable strings which
       are an abbreviated form or description of the domain. */
    media_key_insert(session, "*@pep.foundation", "AA:PEP");
    media_key_insert(session, "*@ageinghacker.net", "BB:AGE");
    /* A pattern like "*@*.ageinghacker.net" would have been more explicit, but
       it is nice to have instead "*ageinghacker.net", which is more general
       than the previous one "*@ageinghacker.net": the media-key map order will
       make (proper) subdomains of ageinghacker.net match "*@ageinghacker.net"
       but not "*ageinghacker.net". */
    media_key_insert(session, "*ageinghacker.net", "BB:AGE-SUBDOMAIN");
    media_key_insert(session, "mailto:*@run-for-your.life", "CC:RUN");
    media_key_insert(session, "?lice@the-world-is-burning.com", "DD:ENJOY");

    /* Do the actual media-key lookups. */
    TEST_KEY("luca@pep.foundation", "AA:PEP");
    TEST_KEY("luca-pep@run-for-your.life", "CC:RUN");
    TEST_KEY("mailto:luca-pep@run-for-your.life", "CC:RUN");
    TEST_KEY("somebodyelse@run-for-your.life", "CC:RUN");
    TEST_KEY("lucasaiu-pep@ageinghacker.net", "BB:AGE");
    TEST_KEY("saiu-pep@ageinghacker.net", "BB:AGE");
    TEST_KEY("pep-saiu@abelson.ageinghacker.net", "BB:AGE-SUBDOMAIN");
    TEST_KEY("saiu-pep@sussman.ageinghacker.net", "BB:AGE-SUBDOMAIN");
    TEST_KEY("alice@the-world-is-burning.com", "DD:ENJOY");
    TEST_KEY("mailto:alice@the-world-is-burning.com", "DD:ENJOY");
    TEST_KEY("blice@the-world-is-burning.com", "DD:ENJOY");
    TEST_KEY("luca@aaargh.com", NULL);
    TEST_KEY("bob@aaargh.com", NULL);
    TEST_KEY("luca-and-bob@aaargh.com", NULL);
    TEST_KEY("luca@elsewhere.com", NULL);
    TEST_KEY("bob@the-world-is-burning.com", NULL);
}

TEST_F(MediaKeyTest, check_removal) {
    PEP_STATUS status = PEP_UNKNOWN_ERROR;

#define CHECK_LOOKUP_FAILURE(ADDRESS)                                 \
    do {                                                              \
        char *key;                                                    \
        status = media_key_lookup_address(session, (ADDRESS), &key);  \
        ASSERT_EQ(status, PEP_KEY_NOT_FOUND);                         \
    } while (false)
#define CHECK_LOOKUP(ADDRESS, EXPTECTED_KEY)                          \
    do {                                                              \
        char *key;                                                    \
        status = media_key_lookup_address(session, (ADDRESS), &key);  \
        ASSERT_EQ(status, PEP_STATUS_OK);                             \
        ASSERT_EQ(strcmp(key, (EXPTECTED_KEY)), 0);                   \
    } while (false)

#define INSERT(ADDRESS, KEY)                                   \
    do {                                                       \
        status = media_key_insert(session, (ADDRESS), (KEY));  \
        ASSERT_EQ(status, PEP_STATUS_OK);                      \
    } while (false)
#define REMOVE(ADDRESS)                                 \
    do {                                                \
        status = media_key_remove(session, (ADDRESS));  \
        ASSERT_EQ(status, PEP_STATUS_OK);               \
    } while (false)
#define CHECK_REMOVE_FAILURE(ADDRESS)                   \
    do {                                                \
        status = media_key_remove(session, (ADDRESS));  \
        ASSERT_EQ(status, PEP_KEY_NOT_FOUND);           \
    } while (false)

    CHECK_REMOVE_FAILURE("*@nonexisting.bar");

    CHECK_LOOKUP_FAILURE("foo@foo.bar");

    INSERT("*@foo.bar",    "foo");
    CHECK_LOOKUP("foo@foo.bar", "FOO");
    CHECK_LOOKUP_FAILURE("bar@bar.bar");

    INSERT("*@bar.bar",    "bar");
    INSERT("*@quux.bar",   "quux");
    INSERT("*@foobar.bar", "foobar");

    CHECK_REMOVE_FAILURE("*@nonexisting.bar");

    REMOVE("*@quux.bar");
    CHECK_LOOKUP_FAILURE("quux@quux.bar");
    CHECK_LOOKUP("foobar@foobar.bar", "FOOBAR");
    CHECK_LOOKUP_FAILURE("foobar@foooooooooobar.bar");
    CHECK_LOOKUP("bar@bar.bar", "BAR");
    CHECK_LOOKUP("foobar@foobar.bar", "FOOBAR");
    REMOVE("*@foobar.bar");
    CHECK_LOOKUP("bar@bar.bar", "BAR");
    CHECK_LOOKUP_FAILURE("foobar@fooobar.bar");

    REMOVE("*@bar.bar");
    CHECK_REMOVE_FAILURE("*@bar.bar");
    CHECK_LOOKUP_FAILURE("bar@fooobar.bar");

    CHECK_REMOVE_FAILURE("*@nonexisting.bar");
    CHECK_LOOKUP_FAILURE("bar@fooobar.bar");

    INSERT("*@bar.bar",    "bar");
    CHECK_LOOKUP("bar@bar.bar", "BAR");
    REMOVE("*@bar.bar");
    CHECK_REMOVE_FAILURE("*@bar.bar");
    CHECK_LOOKUP_FAILURE("bar@bar.bar");

    CHECK_REMOVE_FAILURE("*@nonexisting.bar");
}
