#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include "mime.h"

using namespace std;

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
            new_identity("vb@dingens.org", NULL, NULL, NULL),
            new_identity_list(new_identity("trischa@dingens.org", NULL, NULL, NULL)),
            "my sübject");
    assert(msg2);
    string text2 = "my mèssage to yoü";
    msg2->longmsg = strdup(text2.c_str());
    string html2 = "<html><body><p>my message to you</p></body></html>";
    msg2->longmsg_formatted = strdup(html2.c_str());
    assert(msg2->longmsg_formatted);

    cout << "encoding message…\n";
    char *result2;
    PEP_STATUS status2 = mime_encode_message(msg2, &result2);
    assert(result2);
    assert(status2 == PEP_STATUS_OK);

    cout << "result:\n";
    cout << result2 << "\n";

    free(result2);
    free_message(msg2);

    cout << "calling release()\n";
    release(session);
    return 0;
}

