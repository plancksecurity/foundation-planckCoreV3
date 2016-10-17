#include <iostream>
#include <string>
#include <assert.h>
#include "pEpEngine.h"

using namespace std;

int main() {
    cout << "\n*** trustwords_for_id_pair test ***\n\n";

    PEP_SESSION session;
    
    cout << "calling init()\n";
    PEP_STATUS status1 = init(&session);   
    assert(status1 == PEP_STATUS_OK);
    assert(session);
    cout << "init() completed.\n";
        
    pEp_identity* identity1  = new_identity(
        "leon.schumacher@digitalekho.com",
        "8BD08954C74D830EEFFB5DEB2682A17F7C87F73D",
        "23",
        "Leon Schumacher");
    
    pEp_identity* identity2 = new_identity(
        "krista@kgrothoff.org",
        "62D4932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Grothoff");
    
    string fingerprint1 = identity1->fpr;
    string fingerprint2 = identity2->fpr;
    char* words1;
    char* words2;
    char* full_wordlist;
    size_t wsize1;
    size_t wsize2;
    size_t wsize_full;
    
    cout << "\nfinding German trustwords for " << fingerprint1 << "...\n";
    trustwords(session, fingerprint1.c_str(), "de", &words1, &wsize1, 5);
    assert(words1);
    cout << words1 << "\n";

    cout << "\nfinding German trustwords for " << fingerprint2 << "...\n";
    trustwords(session, fingerprint2.c_str(), "de", &words2, &wsize2, 5);
    assert(words2);
    cout << words2 << "\n";

    cout << "\nfinding German trustwords for " << identity1->address << " and " << identity2->address << "...\n";
    trustwords_for_id_pair(session, identity1, identity2, "de", &full_wordlist, &wsize_full, 5);
    assert(full_wordlist);
    cout << full_wordlist << "\n";
    
    
    pEp_free(words1);
    pEp_free(words2);
    pEp_free(full_wordlist);
    
    
    free(identity1);
    free(identity2);
    cout << "calling release()\n";
    release(session);
    return 0;
}

