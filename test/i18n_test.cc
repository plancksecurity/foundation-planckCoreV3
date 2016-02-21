#include <iostream>
#include <string>
#include <assert.h>
#include "pEpEngine.h"

using namespace std;

int main() {
    cout << "\n*** i18n_test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";

    // i18n test code

    char *languages;
    PEP_STATUS status2 = get_languagelist(session, &languages);
    assert(status2 == PEP_STATUS_OK);
    assert(languages);

    cout << languages;
    pEp_free(languages);

    char *phrase;
    PEP_STATUS status3 = get_phrase(session, "de", 1, &phrase);
    assert(status3 == PEP_STATUS_OK);
    assert(phrase);

    cout << "\nGerman: " << phrase << "\n";
    pEp_free(phrase);

    status3 = get_phrase(session, "zz", 1, &phrase);
    assert(status3 == PEP_PHRASE_NOT_FOUND);
    assert(phrase == NULL);

    cout << "calling release()\n";
    release(session);
    return 0;
}

