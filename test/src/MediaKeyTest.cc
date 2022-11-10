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

TEST_F(MediaKeyTest, check_rating_no_media_key) {
    PEP_STATUS status = PEP_STATUS_OK;
#define S                                  \
    do {                                   \
        ASSERT_EQ(status, PEP_STATUS_OK);  \
    } while (false)

    if (! slurp_and_import_key(session, "test_keys/priv/pep-test-mary-0x7F59F03CD04A226E_priv.asc"))
        { ASSERT_EQ(true, false); }
    const char *media_key_fpr = "599B3D67800DB37E2DCE05C07F59F03CD04A226E";

    /* Make some identities. */
#define MAKE_IDENTITY(variable_name, username, id, email, fpr, key_file,       \
                      has_media_key)                                           \
    pEp_identity *variable_name = new_identity(email, NULL, id, username);     \
    ASSERT_NE(variable_name, (pEp_identity *) NULL);                           \
    /*status = set_identity(session, variable_name); S; */                     \
    if (fpr != NULL) {                                                         \
        status = set_as_pEp_user(session, variable_name);                      \
        S;                                                                     \
    }                                                                          \
    status = update_identity(session, variable_name);                          \
    S;                                                                         \
    /* Apparently it is correct for status to be PEP_KEY_NOT_FOUND here. */    \
    if (fpr != NULL) {                                                         \
        if (! slurp_and_import_key(session, key_file)) {                       \
            ASSERT_EQ(true, false);                                            \
        }                                                                      \
        status = set_comm_partner_key(session, variable_name, fpr);            \
        S;                                                                     \
    }                                                                          \
    if (has_media_key) {                                                       \
        status = media_key_insert(session, email, media_key_fpr);              \
        S;                                                                     \
    }

    MAKE_IDENTITY(keyed_alice, "Alice in the wonderland of keys", "keyed-alice",
                  "keyed-alice@key-wonderland.net",
                  "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97",
                  "/home/luca/pep-src/pep-engine/test/test_keys/pub/pep-test-alice-0x6FF00E97_pub.asc",
                  false);
    MAKE_IDENTITY(keyless_bob, "Keyless Bob", "keyless-bob",
                  "bob@nokey.net",
                  NULL,
                  NULL,
                  false);
    MAKE_IDENTITY(media_key_charles, "Media-Key Charles", "media-key-charles",
                  "charlie@foobar-media-keys.com",
                  NULL,
                  NULL,
                  true);
    MAKE_IDENTITY(both_keys_david, "Both-Keys Dave", "dave-both-keys",
                  "dave@every-way-at-the-same-time.org",
                  "A5B3473EA7CBB5DF7A4F595A8883DC4BCD8BAC06",
                  "test_keys/pub/carol-0xCD8BAC06_pub.asc",
                  true);
    //status = set_trust(session, keyed_alice); S;

    PEP_rating rating = PEP_rating_b0rken;
#define ASSERT_RATING(identity, expected_rating)                  \
    do {                                                          \
        status = identity_rating(session, (identity), & rating);  \
        S;                                                        \
        ASSERT_EQ(rating, (expected_rating));                     \
    } while (false)

    ASSERT_RATING(keyed_alice,       PEP_rating_reliable);
    ASSERT_RATING(keyless_bob,       PEP_rating_have_no_key);
    ASSERT_RATING(media_key_charles, PEP_rating_media_key_protected);
    ASSERT_RATING(both_keys_david,   PEP_rating_reliable);

#undef S
#undef MAKE_IDENTITY
#undef ASSERT_RATING
}
