#pragma one

#include "pEpEngine.h"
#include "stringlist.h"
#include "../asn.1/Identity.h"

Identity_t *Identity_from_Struct(const pEp_identity *ident);
pEp_identity *Identity_to_Struct(Identity_t *ident);
