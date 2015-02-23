#include <iostream>
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

    // testing plain

    string bla2 = "my message to yöu";
    cout << "encoding message…\n";
    char *result2;
    PEP_STATUS status2 = mime_encode_text(bla2.c_str(), NULL, NULL, &result2);
    assert(result2);
    assert(status2 == PEP_STATUS_OK);

    cout << "result:\n";
    cout << result2 << "\n";

    free(result2);

    // testing multipart/alternative

    string bla3 = "my message to yöu";
    string html3 = "<html><body><p>my message to you</p></body></html>";

    cout << "encoding message…\n";
    char *result3;
    PEP_STATUS status3 = mime_encode_text(bla3.c_str(), html3.c_str(), NULL, &result3);
    assert(result3);
    assert(status3 == PEP_STATUS_OK);

    cout << "result:\n";
    cout << result3 << "\n";

    free(result3);

    cout << "calling release()\n";
    release(session);
    return 0;
}

