#include <stdlib.h>
#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pEpEngine.h"
#include "pEp_internal.h"
#include "test_util.h"
#include "TestConstants.h"
#include "Engine.h"

#include <gtest/gtest.h>


namespace {

	//The fixture for EmptyLongmsgFullHtmlTest
    class EmptyLongmsgFullHtmlTest : public ::testing::Test {
        public:
            Engine* engine;
            PEP_SESSION session;

        protected:
            // You can remove any or all of the following functions if its body
            // is empty.
            EmptyLongmsgFullHtmlTest() {
                // You can do set-up work for each test here.
                test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();
                test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
                test_path = get_main_test_home_dir() + "/" + test_suite_name + "/" + test_name;
            }

            ~EmptyLongmsgFullHtmlTest() override {
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
                ASSERT_NOTNULL(engine);

                // Ok, let's initialize test directories etc.
                engine->prep(NULL, NULL, NULL, init_files);

                // Ok, try to start this bugger.
                engine->start();
                ASSERT_NOTNULL(engine->session);
                session = engine->session;

                // Engine is up. Keep on truckin'
            }

            const char* html_text =
                "<html>\n"
                "  <head>\n"
                "    <meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">\n"
                "  </head>\n"
                "  <body>\n"
                "    <table width=\"100%\" cellspacing=\"2\" cellpadding=\"2\" border=\"1\"\n"
                "      bgcolor=\"pink\">\n"
                "      <tbody>\n"
                "        <tr>\n"
                "          <td valign=\"top\" bgcolor=\"pink\"><img moz-do-not-send=\"false\"\n"
                "              src=\"cid:part1.21156198.7E41C8BF@darthmama.org\" alt=\"Tiny\n"
                "              Canth cat\" width=\"144\" height=\"204\"><br>\n"
                "          </td>\n"
                "          <td valign=\"top\"><br>\n"
                "          </td>\n"
                "        </tr>\n"
                "        <tr>\n"
                "          <td valign=\"top\"><br>\n"
                "          </td>\n"
                "          <td valign=\"top\"><br>\n"
                "          </td>\n"
                "        </tr>\n"
                "        <tr>\n"
                "          <td valign=\"top\"><br>\n"
                "          </td>\n"
                "          <td valign=\"top\"><br>\n"
                "          </td>\n"
                "        </tr>\n"
                "      </tbody>\n"
                "    </table>\n"
                "    <p><br>\n"
                "    </p>\n"
                "  </body>\n"
                "</html>\n";

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
            // Objects declared here can be used by all tests in the EmptyLongmsgFullHtmlTest suite.

    };

}  // namespace


TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_NULL) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup("<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n");
    msg->shortmsg = strdup("Eat Moar Cheese");
    
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
    
    cout << outmsg << endl;
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_text_att) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup("<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n");
    msg->shortmsg = strdup("Eat Moar Cheese");
    
    char* text_att = strdup("This is a text attachment.\n");
    msg->attachments = new_bloblist(text_att, strlen(text_att), "text/plain", NULL);
    
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
    
    ASSERT_NULL(strstr(outmsg, "alternative"));
    
    cout << outmsg << endl;
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_html_att) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup("<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n");
    msg->shortmsg = strdup("Eat Moar Cheese");
    
    char* text_att = strdup("This is a text attachment.\n");
    msg->attachments = new_bloblist(text_att, strlen(text_att), "text/plain", NULL);
    
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
    
    ASSERT_NULL(strstr(outmsg, "alternative"));
    ASSERT_NULL(strstr(outmsg, "related"));
    ASSERT_NOTNULL(strstr(outmsg, "mixed"));
            
    cout << outmsg << endl;
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_text_html_atts) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup("<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n");
    msg->shortmsg = strdup("Eat Moar Cheese");
    
    char* text_att = strdup("This is a text attachment.\n");
    msg->attachments = new_bloblist(text_att, strlen(text_att), "text/plain", "texty.txt");
    char* html_att = strdup("<html>\n<body>\n<h1>Warning!</h1>\n<p>Totally wasn't kidding about html mail.</p>\n</body>\n</html>\n");
    bloblist_add(msg->attachments, html_att, strlen(html_att), "text/html", "stupid_msg.html");

    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
    
    // Could do more here, but honestly, these are just sanity checks, as mostly this is getting checked by inspection
    ASSERT_NULL(strstr(outmsg, "alternative"));
    ASSERT_NULL(strstr(outmsg, "related"));
    ASSERT_NOTNULL(strstr(outmsg, "mixed"));
    
    cout << outmsg << endl;
    
    const char* body_html_text = strstr(outmsg, "HTML Mail");
    ASSERT_NOTNULL(body_html_text);
    const char* att_html_text = strstr(body_html_text + 1, "Warning");
    ASSERT_GT(att_html_text, body_html_text);

            
    const char* chkstr = strstr(outmsg, "Content-Disposition: attachment");
    ASSERT_NOTNULL(chkstr);
    chkstr = strstr(chkstr + strlen("Content-Disposition: attachment"), "Content-Disposition: attachment");    
    ASSERT_NOTNULL(chkstr);        
    chkstr = strstr(chkstr + strlen("Content-Disposition: attachment"), "Content-Disposition: attachment");
    ASSERT_NULL(chkstr);
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_html_text_atts) {
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup("<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n");
    msg->shortmsg = strdup("Eat Moar Cheese");
    
    char* html_att = strdup("<html>\n<body>\n<h1>Warning!</h1>\n<p>Totally wasn't kidding about html mail.</p>\n</body>\n</html>\n");
    msg->attachments = new_bloblist(html_att, strlen(html_att), "text/html", "blargh.html");    
    char* text_att = strdup("This is a text attachment.\n");
    msg->attachments->next = new_bloblist(text_att, strlen(text_att), "text/plain", "blargh.txt");
    
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
    
    cout << outmsg << endl;
        
    // Could do more here, but honestly, these are just sanity checks, as mostly this is getting checked by inspection
    ASSERT_NULL(strstr(outmsg, "alternative"));
    ASSERT_NULL(strstr(outmsg, "related"));    
    ASSERT_NOTNULL(strstr(outmsg, "mixed"));    
    const char* body_html_text = strstr(outmsg, "HTML Mail");
    ASSERT_NOTNULL(body_html_text);
    const char* att_html_text = strstr(body_html_text + 1, "Warning");
    ASSERT_GT(att_html_text, body_html_text);
        
    const char* chkstr = strstr(outmsg, "Content-Disposition: attachment");
    ASSERT_NOTNULL(chkstr);
    chkstr = strstr(chkstr + strlen("Content-Disposition: attachment"), "Content-Disposition: attachment");    
    ASSERT_NOTNULL(chkstr);        
    chkstr = strstr(chkstr + strlen("Content-Disposition: attachment"), "Content-Disposition: attachment");
    ASSERT_NULL(chkstr);
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_text_empty) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup("<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n");
    msg->shortmsg = strdup("Eat Moar Cheese");
    msg->longmsg = strdup("");
        
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
        
    cout << outmsg << endl;
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_text_inline_att) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
        
    msg->longmsg_formatted = strdup(html_text);
    msg->shortmsg = strdup("Eat Moar Cheese");
        
    
    int retval = 0;
    
#ifndef WIN32
    struct stat fst;    
    retval = stat("test_files/meow.jpeg", &fst);
#else 
    struct _stat fst;
    retval = _stat("test_files/meow.jpeg", &fst);
#endif 
    
    ASSERT_EQ(retval, 0);
    size_t img_size = (size_t)(fst.st_size);
    ASSERT_NE(img_size, 0);
    char* img = (char*)calloc(1, img_size);
    
    ifstream img_file("test_files/meow.jpeg", ios::in | ios::binary);
    
    img_file.read(img, img_size);
    img_file.close();
    
    msg->attachments = new_bloblist(img, img_size, "image/jpeg", "cid://part1.21156198.7E41C8BF@darthmama.org");
        
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
        
    ASSERT_NULL(strstr(outmsg, "alternative"));
    ASSERT_NOTNULL(strstr(outmsg, "related"));
    ASSERT_NULL(strstr(outmsg, "Content-Disposition: attachment"));
            
    cout << outmsg << endl;
    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_empty_longmsg_full_html_text_inline_att_plus_att) {
    // This is just a dummy test case. The convention is check_whatever_you_are_checking
    // so for multiple test cases in a suite, be more explicit ;)
    pEp_identity* carol = NULL;
    PEP_STATUS status = set_up_preset(session, CAROL, true, true, true, true, true, &carol); 
    pEp_identity* dave = NULL;
    status = set_up_preset(session, DAVE, true, true, true, false, false, &dave);
    
    message* msg = new_message(PEP_dir_outgoing);
    msg->from = carol;
    msg->to = new_identity_list(dave);
    msg->longmsg_formatted = strdup(html_text);
    msg->shortmsg = strdup("Eat Moar Cheese");
            
    int retval = 0;
    
#ifndef WIN32
    struct stat fst;    
    retval = stat("test_files/meow.jpeg", &fst);
#else 
    struct _stat fst;
    retval = _stat("test_files/meow.jpeg", &fst);
#endif 
    
    ASSERT_EQ(retval, 0);
    size_t img_size = (size_t)(fst.st_size);
    ASSERT_NE(img_size, 0);
    char* img = (char*)calloc(1, img_size);
    
    ifstream img_file("test_files/meow.jpeg", ios::in | ios::binary);
    
    img_file.read(img, img_size);
    img_file.close();
    
    // FIXME: When we clean up this test and actually, you know, free the memory, be careful -
    // both data parts of the bloblist are actually the same pointer. Bad form :)
    msg->attachments = new_bloblist(img, img_size, "image/jpeg", "cid://part1.21156198.7E41C8BF@darthmama.org");
    bloblist_add(msg->attachments, img, img_size, "image/jpeg", "meow.jpg");
        
    char* outmsg = NULL;
    mime_encode_message(msg, false, &outmsg, false);
        
    ASSERT_NULL(strstr(outmsg, "alternative"));
    ASSERT_NOTNULL(strstr(outmsg, "related"));
    ASSERT_NOTNULL(strstr(outmsg, "mixed"));      
    ASSERT_NOTNULL(strstr(outmsg, "Content-ID: <part1.21156198.7E41C8BF@darthmama.org>"));
    ASSERT_NOTNULL(strstr(outmsg, "Content-Disposition: attachment; filename=\"meow.jpg\""));
    cout << outmsg << endl;
}

// Ok, let's check the same for the empty html parsing problem
TEST_F(EmptyLongmsgFullHtmlTest, check_parse_simple_html_only) {
    string msg_str = slurp("test_mails/htmlonly_simple.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    
    ASSERT_NOTNULL(msg);
    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NULL(msg->attachments);
    
    cout << msg->longmsg_formatted << endl;
}

TEST_F(EmptyLongmsgFullHtmlTest, check_parse_simple_html_text_attachment) {
    string msg_str = slurp("test_mails/html_with_text_attachment.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    
    ASSERT_NOTNULL(msg);
    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NOTNULL(msg->attachments);
    ASSERT_STREQ(msg->attachments->mime_type, "text/plain");
    string att_txt = "Your mother was a hamster\nAnd your father smelt of elterberries";
    ASSERT_EQ(memcmp(att_txt.c_str(), msg->attachments->value, att_txt.size()), 0);
    ASSERT_NULL(msg->attachments->next);    
    cout << msg->longmsg_formatted << endl;
}

TEST_F(EmptyLongmsgFullHtmlTest, check_parse_simple_html_text_html_attachment) {
    string msg_str = slurp("test_mails/htmlonly_simple_text_html.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    
    ASSERT_NOTNULL(msg);
    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NOTNULL(msg->attachments);
    ASSERT_STREQ(msg->attachments->mime_type, "text/plain");
    string att_txt = "\nBAH.\n";
    ASSERT_EQ(memcmp(att_txt.c_str(), msg->attachments->value, att_txt.size()), 0);
    ASSERT_NOTNULL(msg->attachments->next);    
    ASSERT_STREQ(msg->attachments->next->mime_type, "text/html");
    string html_txt = "<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n";
    ASSERT_EQ(memcmp(html_txt.c_str(), msg->attachments->next->value, html_txt.size()), 0);        
    ASSERT_NULL(msg->attachments->next->next);
}


TEST_F(EmptyLongmsgFullHtmlTest, check_parse_simple_html_html_text_attachment) {
    string msg_str = slurp("test_mails/htmlonly_simple_html_text.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);

    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NOTNULL(msg->attachments);
    ASSERT_NOTNULL(msg->attachments->next);    
    ASSERT_STREQ(msg->attachments->mime_type, "text/html");
    string att_txt = "\nBAH.\n";
    string html_txt = "<html>\n<body>\n<h1>HTML Mail is For Losers</h1>\n<p>But people use it.</p>\n</body>\n</html>\n";
    ASSERT_EQ(memcmp(html_txt.c_str(), msg->attachments->value, html_txt.size()), 0);        
    ASSERT_STREQ(msg->attachments->next->mime_type, "text/plain");
    ASSERT_EQ(memcmp(att_txt.c_str(), msg->attachments->next->value, att_txt.size()), 0);
    ASSERT_NULL(msg->attachments->next->next);
}


TEST_F(EmptyLongmsgFullHtmlTest, check_parse_simple_inline_html) {
    string msg_str = slurp("test_mails/inlinecat.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    
    ASSERT_NOTNULL(msg);
    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NOTNULL(msg->attachments);
    ASSERT_STREQ(msg->attachments->mime_type, "image/jpeg");

    int retval = 0;
#ifndef WIN32
    struct stat fst;    
    retval = stat("test_files/meow.jpeg", &fst);
#else 
    struct _stat fst;
    retval = _stat("test_files/meow.jpeg", &fst);
#endif 
    
    ASSERT_EQ(retval, 0);
    size_t img_size = (size_t)(fst.st_size);
    ASSERT_NE(img_size, 0);
    char* img = (char*)calloc(1, img_size);

    ifstream img_file("test_files/meow.jpeg", ios::in | ios::binary);
    
    img_file.read(img, img_size);
    img_file.close();
    
    ASSERT_EQ(memcmp(img, msg->attachments->value, msg->attachments->size), 0);
    ASSERT_EQ(msg->attachments->disposition, PEP_CONTENT_DISP_INLINE);    
    ASSERT_NULL(msg->attachments->next);    
    cout << msg->longmsg_formatted << endl;    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_parse_inline_html_text_attachment) {
    string msg_str = slurp("test_mails/htmlonlycatwtextatt.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    
    ASSERT_NOTNULL(msg);
    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NOTNULL(msg->attachments);
    
    // there should be 2 attachments
    ASSERT_NOTNULL(msg->attachments->next);
    ASSERT_NULL(msg->attachments->next->next);    
    
    bloblist_t* text_att = NULL;
    bloblist_t* img_att = NULL;    
    if (strcmp("text/plain", msg->attachments->mime_type) == 0) {
        text_att = msg->attachments;
        img_att = msg->attachments->next;        
        ASSERT_STREQ(img_att->mime_type, "image/jpeg");
    }
    else {
        img_att = msg->attachments;
        text_att = msg->attachments->next;
        ASSERT_STREQ(img_att->mime_type, "image/jpeg");
        ASSERT_STREQ(text_att->mime_type, "text/plain");        
    }
        
    string att_txt = "Your mother was a hamster\nAnd your father smelt of elterberries";
    ASSERT_EQ(memcmp(att_txt.c_str(), text_att->value, att_txt.size()), 0);
    ASSERT_EQ(text_att->disposition, PEP_CONTENT_DISP_ATTACHMENT);    
    ASSERT_STREQ(text_att->filename, "file://blargh.txt");
    
    ASSERT_EQ(img_att->disposition, PEP_CONTENT_DISP_INLINE);
    ASSERT_STREQ(img_att->filename, "cid://part1.21156198.7E41C8BF@darthmama.org");
    
    cout << msg->longmsg_formatted << endl;    
}

TEST_F(EmptyLongmsgFullHtmlTest, check_parse_inline_html_img_attachment) {
    string msg_str = slurp("test_mails/htmlonlycatwithMOARCAT.eml");
    message* msg = NULL;
    int size = 0;
    mime_decode_message(msg_str.c_str(), msg_str.size(), &msg, NULL);
    
    ASSERT_NOTNULL(msg);
    ASSERT_NULL(msg->longmsg);
    ASSERT_NOTNULL(msg->longmsg_formatted);
    ASSERT_NOTNULL(msg->attachments);
    
    // there should be 2 attachments
    ASSERT_NOTNULL(msg->attachments->next);
    ASSERT_NULL(msg->attachments->next->next);    
    
    bloblist_t* img_not_inline_att = NULL;
    bloblist_t* img_inline_att = NULL;
    
    if (msg->attachments->disposition == PEP_CONTENT_DISP_INLINE) {
        img_inline_att = msg->attachments;
        img_not_inline_att = msg->attachments->next;
    }   
    else {
        img_inline_att = msg->attachments;
        img_not_inline_att = msg->attachments->next;
        ASSERT_EQ(img_inline_att->disposition, PEP_CONTENT_DISP_INLINE);        
    }     
    ASSERT_EQ(img_not_inline_att->disposition, PEP_CONTENT_DISP_ATTACHMENT);
    ASSERT_STREQ(img_inline_att->mime_type, "image/jpeg");
    ASSERT_STREQ(img_not_inline_att->mime_type, "image/jpeg");
                
    string att_txt = "Your mother was a hamster\nAnd your father smelt of elterberries";
    ASSERT_STREQ(img_not_inline_att->filename, "file://meow.jpeg");   
    ASSERT_STREQ(img_inline_att->filename, "cid://part1.AC060ED3.AD29176B@darthmama.org");
    
    output_stream << msg->longmsg_formatted << endl;
}
