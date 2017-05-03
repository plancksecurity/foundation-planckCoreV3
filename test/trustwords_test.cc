// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <iostream>
#include <string>
#include <cassert>
#include "pEpEngine.h"
#include "message_api.h"

using namespace std;


int main() {
    cout << "\n*** get_trustwords test ***\n\n";

    PEP_SESSION session = nullptr;
    
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
    
    pEp_identity* identity2_with_spaces = new_identity(
        "krista@kgrothoff.org",
        " 62D4932086185C159 17B72D30571A FBCA    5493553   ",
        "blargh",
        "Krista Grothoff");
    
    string fingerprint1 = identity1->fpr;
    string fingerprint2 = identity2->fpr;
    char* words1 = nullptr;
    char* words2 = nullptr;
    char* full_wordlist = nullptr;
    size_t wsize1 = 0;
    size_t wsize2 = 0;
    size_t wsize_full = 0;
    
    cout << "\nTest 1: fpr1 > fpr2, short" << endl;
    
    cout << "\nfinding German trustwords for " << fingerprint1 << "...\n";
    trustwords(session, fingerprint1.c_str(), "de", &words1, &wsize1, 5);
    assert(words1);
    cout << words1 << "\n";

    cout << "\nfinding German trustwords for " << fingerprint2 << "...\n";
    trustwords(session, fingerprint2.c_str(), "de", &words2, &wsize2, 5);
    assert(words2);
    cout << words2 << "\n";

    cout << "\nfinding German trustwords for " << identity1->address << " and " << identity2->address << "...\n";
    get_trustwords(session, identity1, identity2, "de", &full_wordlist, &wsize_full, false);
    assert(full_wordlist);
    cout << full_wordlist << "\n";

    cout << "\nfinding German trustwords for " << identity1->address << " and " << identity2->address << "...\n";
    get_trustwords(session, identity1, identity2_with_spaces, "de", &full_wordlist, &wsize_full, false);
    assert(full_wordlist);
    cout << full_wordlist << "\n";
    
    
    pEp_free(words1);
    words1 = nullptr;
    pEp_free(words2);
    words2 = nullptr;
    pEp_free(full_wordlist);
    full_wordlist = nullptr;

    cout << "\nTest 2: fpr1 == fpr1, short" << endl;
    
    cout << "\nfinding French trustwords for " << fingerprint2 << "...\n";
    trustwords(session, fingerprint1.c_str(), "fr", &words1, &wsize1, 5);
    assert(words1);
    cout << words1 << "\n";
        
    cout << "\nfinding French trustwords for " << identity2->address << " and " << identity2->address << "...\n";
    get_trustwords(session, identity2, identity2, "fr", &full_wordlist, &wsize_full, false);
    assert(full_wordlist);
    cout << full_wordlist << "\n";

    cout << "\nfinding French trustwords for " << identity2->address << " and " << identity2->address << "...\n";
    get_trustwords(session, identity2, identity2_with_spaces, "fr", &full_wordlist, &wsize_full, false);
    assert(full_wordlist);
    cout << full_wordlist << "\n";

    pEp_free(words1);
    words1 = nullptr;
    pEp_free(full_wordlist);
    full_wordlist = nullptr;

    cout << "\nTest 3: fpr1 < fpr2, long" << endl;
    
    cout << "\nfinding English trustwords for " << fingerprint2 << "...\n";
    trustwords(session, fingerprint2.c_str(), "en", &words1, &wsize1, 0);
    assert(words1);
    cout << words1 << "\n";
    
    cout << "\nfinding English trustwords for " << fingerprint1 << "...\n";
    trustwords(session, fingerprint1.c_str(), "en", &words2, &wsize2, 0);
    assert(words2);
    cout << words2 << "\n";
    
    cout << "\nfinding English trustwords for " << identity2->address << " and " << identity2->address << "...\n";
    get_trustwords(session, identity2, identity1, "en", &full_wordlist, &wsize_full, true);
    assert(full_wordlist);
    cout << full_wordlist << "\n";
    
    cout << "\nfinding English trustwords for " << identity2->address << " and " << identity2->address << "...\n";
    get_trustwords(session, identity2_with_spaces, identity1, "en", &full_wordlist, &wsize_full, true);
    assert(full_wordlist);
    cout << full_wordlist << "\n";
    
    pEp_free(words1);
    words1 = nullptr;
    pEp_free(words2);
    words2 = nullptr;
    pEp_free(full_wordlist);
    full_wordlist = nullptr;
    
    cout << "\nTest 4: fpr1 < fpr2, leading zeros (fpr1 has more), long" << endl;
    
    pEp_identity* identity3 = new_identity(
        "nobody@kgrothoff.org",
        "000F932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Grothoff");
    
    pEp_identity* identity4 = new_identity(
        "nobody2@kgrothoff.org",
        "001F932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Grothoff");
    
    pEp_identity* identity5 = new_identity(
        "nobody3@kgrothoff.org",
        "001F732086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Grothoff");

    string fingerprint3 = identity3->fpr;
    string fingerprint4 = identity4->fpr;
    string fingerprint5 = identity5->fpr; 
        
    cout << "\nfinding Catalan trustwords for " << fingerprint3 << "...\n";
    trustwords(session, fingerprint3.c_str(), "ca", &words1, &wsize1, 0);
    assert(words1);
    cout << words1 << "\n";
    
    cout << "\nfinding Catalan trustwords for " << fingerprint4 << "...\n";
    trustwords(session, fingerprint4.c_str(), "ca", &words2, &wsize2, 0);
    assert(words2);
    cout << words2 << "\n";
    
    cout << "\nfinding Catalan trustwords for " << identity3->address << " and " << identity4->address << "...\n";
    get_trustwords(session, identity3, identity4, "ca", &full_wordlist, &wsize_full, true);
    assert(full_wordlist);
    cout << full_wordlist << "\n";

    pEp_free(words1);
    words1 = nullptr;
    pEp_free(words2);
    words2 = nullptr;
    pEp_free(full_wordlist);
    full_wordlist = nullptr;

    cout << "\nTest 5: fpr1 > fpr2, leading zeros (same number), interior digit difference, short" << endl;
    
    cout << "\nfinding Turkish trustwords for " << fingerprint4 << "...\n";
    trustwords(session, fingerprint4.c_str(), "tr", &words1, &wsize1, 5);
    assert(words1);
    cout << words1 << "\n";
    
    cout << "\nfinding Turkish trustwords for " << fingerprint5 << "...\n";
    trustwords(session, fingerprint5.c_str(), "tr", &words2, &wsize2, 5);
    assert(words2);
    cout << words2 << "\n";
    
    cout << "\nfinding Turkish trustwords for " << identity4->address << " and " << identity5->address << "...\n";
    get_trustwords(session, identity4, identity5, "tr", &full_wordlist, &wsize_full, false);
    assert(full_wordlist);
    cout << full_wordlist << "\n";
    
    pEp_free(words1);
    words1 = nullptr;
    pEp_free(words2);
    words2 = nullptr;
    pEp_free(full_wordlist);
    full_wordlist = nullptr;

    cout << "\nTest 6: fpr2 is too short" << endl;
    
    pEp_identity* identity6 = new_identity(
        "nobody4@kgrothoff.org",
        "01F932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Grothoff");
    
    cout << "\nfinding Turkish trustwords for " << identity5->address << " and " << identity6->address << "...\n";
    PEP_STATUS status6 = get_trustwords(session, identity5, identity6, "tr", &full_wordlist, &wsize_full, false);
    assert(status6 == PEP_TRUSTWORDS_FPR_WRONG_LENGTH);
    cout << "Bad fpr length correctly recognised." << "\n";
    
    pEp_identity* identity7 = new_identity(
        "nobody5@kgrothoff.org",
        "F01X932086185C15917B72D30571AFBCA5493553",
        "blargh",
        "Krista Grothoff");

    cout << "\nTest 7: fpr2 has a non-hex character" << endl;
    
    cout << "\nfinding Turkish trustwords for " << identity1->address << " and " << identity7->address << "...\n";
    PEP_STATUS status7 = get_trustwords(session, identity1, identity7, "tr", &full_wordlist, &wsize_full, true);
    assert(status7 == PEP_ILLEGAL_VALUE);
    cout << "Illegal digit value correctly recognised." << "\n";
    
    
    free_identity(identity1);
    free_identity(identity2);
    free_identity(identity3);
    free_identity(identity4);
    free_identity(identity5);
    free_identity(identity6);
    free_identity(identity7);
    
    cout << "calling release()\n";
    release(session);
    return 0;
}

