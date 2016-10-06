#pragma once

#include "pEpEngine.h"
#include "identity_list.h"
#include "../asn.1/Identity.h"
#include "../asn.1/IdentityList.h"
#include "../asn.1/GeneralizedTime.h"

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


// IdentityList_from_identity_list() - convert identity_list_t into ASN.1 IdentityList_t
//
//  params:
//      list (in)           identity_list to convert
//      result (inout)      IdentityList_t to update or NULL to alloc a new one
//
//  return value:
//      pointer to updated or allocated result
//
//  caveat:
//      if a new struct is allocated, the ownership goes to the caller

IdentityList_t *IdentityList_from_identity_list(
        const identity_list *list,
        IdentityList_t *result
    );

// IdentityList_to_identity_list() - convert ASN.1 IdentityList_t to identity_list_t
//
//  params:
//      list (in)           ASN.1 IdentityList_t to convert
//      result (inout)      identity_list_t to update or NULL to alloc a new one
//
//  return value:
//      pointer to updated or allocated result
//
//  caveat:
//      if a new struct is allocated, the ownership goes to the caller

identity_list *IdentityList_to_identity_list(IdentityList_t *list, identity_list *result);

// GeneralizedTime_to_timestamp() - convert ASN.1 GeneralizedTime to timestamp
//
//  params:
//      asntime (in)        ASN.1 GeneralizedTime to convert
//      result (inout)      timestamp to update or NULL to alloc a new one
//
//  return value:
//      pointer to allocated timestamp
//
//  caveat:
//      if a new timestamp is allocated, the ownership goes to the caller

timestamp *GeneralizedTime_to_timestamp(GeneralizedTime_t * asntime, timestamp *result);

// GeneralizedTime_to_time_t() - convert ASN.1 GeneralizedTime to time_t
//
//  params:
//      asntime (in)        ASN.1 GeneralizedTime to convert
//
//  return value:
//      resulting time_t
//

time_t GeneralizedTime_to_time_t(GeneralizedTime_t * asntime);

// timestamp_GeneralizedTime_to() - convert ASN.1 timestamp to GeneralizedTime
//
//  params:
//      ts (in)             timestam to convert
//      result (inout)      GeneralizedTime_t to update or NULL to alloc a new one
//
//  return value:
//      pointer to allocated ASN.1 GeneralizedTime
//
//  caveat:
//      if a new GeneralizedTime is allocated, the ownership goes to the caller

GeneralizedTime_t *timestamp_to_GeneralizedTime(timestamp * ts, GeneralizedTime_t *result);

#ifdef __cplusplus
}
#endif

