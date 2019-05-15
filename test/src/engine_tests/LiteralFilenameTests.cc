// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>
#include <fstream>

#include "pEpEngine.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "LiteralFilenameTests.h"

using namespace std;

LiteralFilenameTests::LiteralFilenameTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("LiteralFilenameTests::check"),
                                                                      static_cast<Func>(&LiteralFilenameTests::check)));
}

void LiteralFilenameTests::check() {
    slurp_and_import_key(session, "test_keys/priv/pep-test-lisa-0xBA0997C1514E70EB_priv.asc");

    string ciphertext = slurp("test_files/literal-packet-with-filename.pgp");

    // Decrypt and verify it.
    char *plaintext = NULL;
    size_t plaintext_size = 0;
    stringlist_t *keylist = NULL;
    char *filename = NULL;
    PEP_STATUS status = decrypt_and_verify(session,
                                           ciphertext.c_str(),
                                           ciphertext.size(),
                                           NULL, 0,
                                           &plaintext, &plaintext_size,
                                           &keylist, &filename);

    TEST_ASSERT_MSG(status == PEP_DECRYPTED_AND_VERIFIED, tl_status_string(status));
    TEST_ASSERT_MSG(filename, "filename");
    TEST_ASSERT_MSG((strcmp(filename, "filename.txt") == 0), "strcmp(filename, \"filename.txt\") == 0");
}
