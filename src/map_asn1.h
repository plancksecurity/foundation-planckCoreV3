#pragma one

#include "pEpEngine.h"
#include "stringlist.h"
#include "../asn.1/Identity.h"
#include "../asn.1/KeyList.h"

#ifdef __cplusplus
extern "C" {
#endif


// Identity_from_Struct() - convert pEp_identity into ASN.1 Identity_t
//
//  params:
//      ident (in)          pEp_identity to convert
//      result (inout)      Identity_t to update or NULL to alloc a new one
//
//  return value:
//      pointer to updated or allocated result
//
//  caveat:
//      if a new struct is allocated, the ownership goes to the caller

Identity_t *Identity_from_Struct(
        const pEp_identity *ident,
        Identity_t *result
    );


// Identity_to_Struct() - convert ASN.1 Identity_t into pEp_identity
//
//  params:
//      ident (in)          Identity_t to convert
//      result (inout)      pEp_identity to update or NULL to alloc a new one
//
//  return value:
//      pointer to updated or allocated result
//
//  caveat:
//      if a new struct is allocated, the ownership goes to the caller

pEp_identity *Identity_to_Struct(Identity_t *ident, pEp_identity *result);


// KeyList_from_stringlist() - convert stringlist_t into ASN.1 KeyList_t
//
//  params:
//      list (in)           stringlist_t to convert
//      result (inout)      KeyList_t to update or NULL to alloc a new one
//
//  return value:
//      pointer to updated or allocated result
//
//  caveat:
//      if a new struct is allocated, the ownership goes to the caller

KeyList_t *KeyList_from_stringlist(
        const stringlist_t *list,
        KeyList_t *result
    );

// KeyList_to_stringlist() - convert ASN.1 KeyList_t to stringlist_t
//
//  params:
//      list (in)           ASN.1 KeyList_t to convert
//      result (inout)      stringlist_t to update or NULL to alloc a new one
//
//  return value:
//      pointer to updated or allocated result
//
//  caveat:
//      if a new struct is allocated, the ownership goes to the caller

stringlist_t *KeyList_to_stringlist(KeyList_t *list, stringlist_t *result);


#ifdef __cplusplus
}
#endif

