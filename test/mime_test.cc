#include "platform.h"

#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>

#include "mime.h"

using namespace std;

void test_mime_decoding(string filename) {
    cout << "opening " << filename << " for reading\n";
    ifstream inFile3 (filename);
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
            outFile3.write(_b->data, _b->size);
            outFile3.close();
        }
    }

    free_message(msg3);
}

int main() {
    cout << "\n*** mime_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // mime test code

    // testing multipart/alternative

    message *msg2 = new_message(PEP_dir_incoming,
            new_identity("vb@dingens.org", NULL, NULL, "Volker Birk"),
            new_identity_list(new_identity("trischa@dingens.org", NULL, NULL, "Patricia Bädnar")),
            "my sübject");
    assert(msg2);
    string text2 = "my mèssage to yoü";
    msg2->longmsg = strdup(text2.c_str());
    string html2 = "<html><body><p>my message to you</p></body></html>";
    msg2->longmsg_formatted = strdup(html2.c_str());
    assert(msg2->longmsg_formatted);

    cout << "encoding message…\n";
    char *result2;
    PEP_STATUS status2 = mime_encode_message(msg2, false, &result2);
    assert(result2);
    assert(status2 == PEP_STATUS_OK);

    cout << "result:\n";
    cout << result2 << "\n";

    free(result2);
    free_message(msg2);

    test_mime_decoding("msg1.asc");
    test_mime_decoding("msg2.asc");
    test_mime_decoding("msg3.asc");

    cout << "calling release()\n";
    release(session);
    return 0;
}

