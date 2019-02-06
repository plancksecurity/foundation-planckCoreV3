// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <iostream>

#include "pEpEngine.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "I18nTests.h"

using namespace std;

I18nTests::I18nTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("I18nTests::check_i18n"),
                                                                      static_cast<Func>(&I18nTests::check_i18n)));
}

void I18nTests::check_i18n() {

    // i18n test code

    char *languages;
    PEP_STATUS status2 = get_languagelist(session, &languages);
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((languages), "languages");

    cout << languages;
    pEp_free(languages);

    char *phrase;
    PEP_STATUS status3 = get_phrase(session, "de", 1000, &phrase);
    TEST_ASSERT_MSG((status3 == PEP_STATUS_OK), "status3 == PEP_STATUS_OK");
    TEST_ASSERT_MSG((phrase), "phrase");

    cout << "\nGerman: " << phrase << "\n";
    pEp_free(phrase);

    status3 = get_phrase(session, "zz", 1000, &phrase);
    TEST_ASSERT_MSG((status3 == PEP_PHRASE_NOT_FOUND), "status3 == PEP_PHRASE_NOT_FOUND");
    TEST_ASSERT_MSG((phrase == NULL), "phrase == NULL");
}
