// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include "TestConstants.h"
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <assert.h>

#include "pEpEngine.h"
#include "platform.h"
#include "mime.h"

#include <cpptest.h>
#include "EngineTestSessionSuite.h"
#include "MimeTests.h"

using namespace std;

MimeTests::MimeTests(string suitename, string test_home_dir) :
    EngineTestSessionSuite::EngineTestSessionSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("MimeTests::check_mime"),
                                                                      static_cast<Func>(&MimeTests::check_mime)));
}

// FIXME: refactor so we can assert
static void test_mime_decoding(string filename) {
    cout << "opening " << filename << " for reading\n";
    ifstream inFile3 (filename.c_str());

    assert(inFile3.is_open());

    string mimetext3;

    cout << "reading mime sample\n";
    while (!inFile3.eof()) {
        static string line;
        getline(inFile3, line);
        mimetext3 += line + "\n";
    }
    inFile3.close();

    cout << "decoding message…\n";
    message *msg3;
    PEP_STATUS status3 = mime_decode_message(mimetext3.c_str(), mimetext3.length(), &msg3);
    assert(status3 == PEP_STATUS_OK);
    assert(msg3);
    cout << "decoded.\n\n";
    cout << "Subject: " << msg3->shortmsg << "\n\n";
    if (msg3->longmsg)
        cout << msg3->longmsg << "\n\n";
    if (msg3->longmsg_formatted)
        cout << msg3->longmsg_formatted << "\n\n";
    bloblist_t *_b;
    for (_b = msg3->attachments; _b; _b = _b->next) {
        cout << "attachment of type " << _b->mime_type << "\n";
        if (_b->filename) {
            cout << "filename: " << _b->filename << "\n";
            unlink(_b->filename);
            ofstream outFile3(_b->filename);
            outFile3.write(_b->value, _b->size);
            outFile3.close();
        }
    }

    free_message(msg3);
}

void MimeTests::check_mime() {

    // testing multipart/alternative

    message *msg2 = new_message(PEP_dir_incoming);
    TEST_ASSERT_MSG((msg2), "msg2");
    msg2->from = new_identity("vb@dingens.org", NULL, NULL, "Volker Birk");
    msg2->to = new_identity_list(new_identity("trischa@dingens.org", NULL, NULL, "Patricia Bädnar")),
    msg2->shortmsg = strdup("my sübject");

    string text2 = "my mèssage to yoü";
    msg2->longmsg = strdup(text2.c_str());
    string html2 = "<html><body><p>my message to you</p></body></html>";
    msg2->longmsg_formatted = strdup(html2.c_str());
    TEST_ASSERT_MSG((msg2->longmsg_formatted), "msg2->longmsg_formatted");

    cout << "encoding message…\n";
    char *result2;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &result2);
    TEST_ASSERT_MSG((result2), "result2");
    TEST_ASSERT_MSG((status2 == PEP_STATUS_OK), "status2 == PEP_STATUS_OK");

    cout << "result:\n";
    cout << result2 << "\n";

    free(result2);
    free_message(msg2);

    test_mime_decoding("msg1.asc");
    test_mime_decoding("msg2.asc");
    test_mime_decoding("msg3.asc");
}
