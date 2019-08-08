// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "TestConstants.h"
#include <stdlib.h>
#include <string>
#include <cstring>
#include <cpptest.h>

#include "pEpEngine.h"
#include "message.h"
#include "mime.h"
#include "test_util.h"

#include "EngineTestIndividualSuite.h"
#include "SimpleBodyNotAltTests.h"

using namespace std;

SimpleBodyNotAltTests::SimpleBodyNotAltTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SimpleBodyNotAltTests::check_text_w_html_attach"),
                                                                      static_cast<Func>(&SimpleBodyNotAltTests::check_text_w_html_attach)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("SimpleBodyNotAltTests::check_html_w_text_attach"),
                                                                      static_cast<Func>(&SimpleBodyNotAltTests::check_html_w_text_attach)));
}

void SimpleBodyNotAltTests::check_text_w_html_attach() {
    string msg = slurp("test_mails/text message with html attach.eml");
    message* parsed = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &parsed, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(parsed);
    TEST_ASSERT(parsed->longmsg);
    TEST_ASSERT(parsed->longmsg_formatted == NULL);
    TEST_ASSERT_MSG(parsed->attachments, "HTML attachment not preserved.");
    TEST_ASSERT_MSG(parsed->attachments->next == NULL, "Parsing added attachments?!?!");    
    TEST_ASSERT_MSG(parsed->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(parsed->attachments->filename, "file://index.html") == 0, parsed->attachments->filename);    
    TEST_ASSERT_MSG(parsed->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(parsed->attachments->mime_type, "text/html") == 0, parsed->attachments->mime_type);    
    free_message(parsed);
}

void SimpleBodyNotAltTests::check_html_w_text_attach() {
    string msg = slurp("test_mails/HTML-only body w text attachment.eml");
    message* parsed = NULL;

    PEP_STATUS status = mime_decode_message(msg.c_str(), msg.size(), &parsed, NULL);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(parsed);
    TEST_ASSERT(parsed->longmsg == NULL);
    TEST_ASSERT(parsed->longmsg_formatted);
    TEST_ASSERT_MSG(parsed->attachments, "Text attachment not preserved.");
    TEST_ASSERT_MSG(parsed->attachments->next == NULL, "Parsing added attachments?!?!");    
    TEST_ASSERT_MSG(parsed->attachments->filename, "Attachment doesn't have a filename");
    TEST_ASSERT_MSG(strcmp(parsed->attachments->filename, "file://cheese.txt") == 0, parsed->attachments->filename);    
    TEST_ASSERT_MSG(parsed->attachments->mime_type, "Attachment doesn't have a mime type");
    TEST_ASSERT_MSG(strcmp(parsed->attachments->mime_type, "text/plain") == 0, parsed->attachments->mime_type);    
    free_message(parsed);
}
