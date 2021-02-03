/**
 * @file    map_asn1.h
 * @brief   map asn1 to pEp structs and back
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef MAP_ASN1_H
#define MAP_ASN1_H

#include "pEpEngine.h"
#include "identity_list.h"
#include "../asn.1/Identity.h"
#include "../asn.1/IdentityList.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  <!--       Identity_from_Struct()       -->
 *  
 *  @brief Convert pEp_identity into ASN.1 Identity_t
 *  
 *  params:
 *  ident (in)          pEp_identity to convert
 *  result (inout)      Identity_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

Identity_t *Identity_from_Struct(
        const pEp_identity *ident,
        Identity_t *result
    );


/**
 *  <!--       Identity_to_Struct()       -->
 *  
 *  @brief Convert ASN.1 Identity_t into pEp_identity
 *  
 *  params:
 *  ident (in)          Identity_t to convert
 *  result (inout)      pEp_identity to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

pEp_identity *Identity_to_Struct(Identity_t *ident, pEp_identity *result);


/**
 *  <!--       IdentityList_from_identity_list()       -->
 *  
 *  @brief Convert identity_list_t into ASN.1 IdentityList_t
 *  
 *  params:
 *  list (in)           identity_list to convert
 *  result (inout)      IdentityList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

IdentityList_t *IdentityList_from_identity_list(
        const identity_list *list,
        IdentityList_t *result
    );

/**
 *  <!--       IdentityList_to_identity_list()       -->
 *  
 *  @brief Convert ASN.1 IdentityList_t to identity_list_t
 *  
 *  params:
 *  list (in)           ASN.1 IdentityList_t to convert
 *  result (inout)      identity_list_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

identity_list *IdentityList_to_identity_list(IdentityList_t *list, identity_list *result);

#ifdef __cplusplus
}
#endif

#endif
