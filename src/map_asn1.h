#pragma one

#include "pEpEngine.h"
#include "stringlist.h"
#include "../asn.1/Identity.h"
#include "../asn.1/KeyList.h"

#ifdef __cplusplus
extern "C" {
#endif

Identity_t *Identity_from_Struct(const pEp_identity *ident);
pEp_identity *Identity_to_Struct(Identity_t *ident);
KeyList_t *KeyList_from_stringlist(const stringlist_t *list);
stringlist_t *KeyList_to_stringlist(KeyList_t *list);

#ifdef __cplusplus
}
#endif

