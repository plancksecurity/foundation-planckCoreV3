#include <iostream>
#include <string>
#include <cstring>
#include <assert.h>
#include "map_asn1.h"

using namespace std;

int main() {
    cout << "\n*** map_asn1_test ***\n\n";

    cout << "creating new identity...\n";

    pEp_identity *ident1 = new_identity("vb@dingens.org",
            "DB4713183660A12ABAFA7714EBE90D44146F62F4", "42", "Volker Birk");
    assert(ident1);
    ident1->lang[0] = 'd';
    ident1->lang[1] = 'e';
    ident1->comm_type = PEP_ct_pEp;

    cout << "converting identity to ASN.1...\n";

    Identity_t *ident_asn1 = Identity_from_Struct(ident1);
    assert(ident_asn1);

    cout << "converting identity from ASN.1...\n";

    pEp_identity *ident2 = Identity_to_Struct(ident_asn1);
    assert(ident2);

    assert(strcmp(ident1->address, ident2->address) == 0);
    assert(strcmp(ident1->fpr, ident2->fpr) == 0);
    assert(strcmp(ident1->user_id, ident2->user_id) == 0);
    assert(strcmp(ident1->username, ident2->username) == 0);
    assert(ident2->comm_type == PEP_ct_pEp);
    assert(strcmp(ident2->lang, "de") == 0);

    cout << "freeing identities...\n";

    asn_DEF_Identity.free_struct(&asn_DEF_Identity, ident_asn1, 0);
    free_identity(ident1);
    free_identity(ident2);

    cout << "creating new stringlist...\n";

    stringlist_t *sl = new_stringlist("23");
    assert(sl);
    stringlist_t *_sl = stringlist_add(sl, "42");
    assert(_sl);

    cout << "converting stringlist to keylist...\n";

    KeyList_t *kl = KeyList_from_stringlist(sl);
    assert(kl);

    cout << "converting keylist to stringlist...\n";

    stringlist_t *sl2 = KeyList_to_stringlist(kl);
    assert(sl2);

    stringlist_t *_sl2;
    for (_sl = sl, _sl2 = sl2; _sl && _sl->value; _sl = _sl->next, _sl2 = _sl2->next) {
        assert(_sl2);
        assert(_sl2->value);
        assert(strcmp(_sl->value, _sl2->value) == 0);
        assert(!_sl->next == !_sl2->next);
    }

    cout << "freeing lists...\n";

    free_stringlist(sl);
    free_stringlist(sl2);
    ASN_STRUCT_FREE(asn_DEF_KeyList, kl);

    return 0;
}

