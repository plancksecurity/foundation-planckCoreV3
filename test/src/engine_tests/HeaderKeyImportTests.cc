// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "HeaderKeyImportTests.h"

using namespace std;

HeaderKeyImportTests::HeaderKeyImportTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::check_header_key_import"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::check_header_key_import)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_unpadded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_padded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_padded)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_unpadded"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_unpadded)));
}

void HeaderKeyImportTests::base_64_minimal_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_unpadded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded() {
    TEST_ASSERT(true);
}


void HeaderKeyImportTests::base_64_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_unpadded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_leading_whitespace_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_leading_whitespace_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_leading_whitespace_unpadded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_trailing_whitespace_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_trailing_whitespace_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_trailing_whitespace_unpadded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::check_header_key_import() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_kitchen_sink_round() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_kitchen_sink_padded() {
    TEST_ASSERT(true);
}

void HeaderKeyImportTests::base_64_kitchen_sink_unpadded() {
    TEST_ASSERT(true);
}
