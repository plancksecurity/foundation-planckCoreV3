/**
 * @file    map_asn1.h
 * @brief   map asn1 to pEp structs and back
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef MAP_ASN1_H
#define MAP_ASN1_H

#include "message.h"
#include "../asn.1/ASN1Message.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  <!--       Identity_from_Struct()       -->
 *  
 *  @brief Convert pEp_identity into ASN.1 Identity_t
 *  
 *  @param ident[in]           pEp_identity to convert
 *  @param result[in,out]      Identity_t to update or NULL to alloc a new one
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
 *  @param ident[in]          Identity_t to convert
 *  @param result[inout]      pEp_identity to update or NULL to alloc a new one
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
 *  @param list[in]           identity_list to convert
 *  @param result[inout]      IdentityList_t to update or NULL to alloc a new one
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
 *  @param list[in]           ASN.1 IdentityList_t to convert
 *  @param result[inout]      identity_list_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

identity_list *IdentityList_to_identity_list(IdentityList_t *list, identity_list *result);


/**
 *  <!--       StringPair_from_Struct()       -->
 *  
 *  @brief Convert stringpair_t into ASN.1 StringPair_t
 *  
 *  @param value[in]           stringpair_t to convert
 *  @param result[in,out]      StringPair_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

StringPair_t *StringPair_from_Struct(
        const stringpair_t *value,
        StringPair_t *result
    );


/**
 *  <!--       StringPair_to_Struct()       -->
 *  
 *  @brief Convert ASN.1 StringPair_t into stringpair_t
 *  
 *  @param value[in]          StringPair_t to convert
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning a new struct is allocated, the ownership goes to the caller
 *  
 */

stringpair_t *StringPair_to_Struct(StringPair_t *value);


/**
 *  <!--       StringPairList_from_stringpair_list()       -->
 *  
 *  @brief Convert stringpair_list_t into ASN.1 StringPairList_t
 *  
 *  @param list[in]           stringpair_list to convert
 *  @param result[inout]      StringPairList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

StringPairList_t *StringPairList_from_stringpair_list(
        const stringpair_list_t *list,
        StringPairList_t *result
    );

/**
 *  <!--       StringPairList_to_stringpair_list()       -->
 *  
 *  @brief Convert ASN.1 StringPairList_t to stringpair_list_t
 *  
 *  @param list[in]           ASN.1 StringPairList_t to convert
 *  @param result[inout]      stringpair_list_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

stringpair_list_t *StringPairList_to_stringpair_list(
        StringPairList_t *list,
        stringpair_list_t *result
    );


/**
 *  <!--       PStringList_from_stringlist()       -->
 *  
 *  @brief Convert stringlist_t into ASN.1 PStringList_t
 *  
 *  @param list[in]           stringlist to convert
 *  @param result[inout]      PStringList_t to update or NULL to alloc a new one
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

PStringList_t *PStringList_from_stringlist(
        const stringlist_t *list,
        PStringList_t *result
    );

/**
 *  <!--       PStringList_to_stringlist()       -->
 *  
 *  @brief Convert ASN.1 PStringList_t to stringlist_t
 *  
 *  @param list[in]           ASN.1 PStringList_t to convert
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning a new struct is allocated, the ownership goes to the caller
 *  
 */

stringlist_t *PStringList_to_stringlist(PStringList_t *list);


/**
 *  <!--       BlobList_from_bloblist()       -->
 *  
 *  @brief Convert bloblist_t into ASN.1 BlobList_t
 *  
 *  @param list[in]           bloblist to convert
 *  @param result[inout]      BlobList_t to update or NULL to alloc a new one
 *  @param copy               copy data if true, move data otherwise
 *  @param max_blob_size      reject if sum(blob.size) > max_blob_size
 *                            to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

BlobList_t *BlobList_from_bloblist(
        bloblist_t *list,
        BlobList_t *result,
        bool copy,
        size_t max_blob_size
    );


/**
 *  <!--       BlobList_to_bloblist()       -->
 *  
 *  @brief Convert ASN.1 BlobList_t to bloblist_t
 *  
 *  @param list[in]           ASN.1 BlobList_t to convert
 *  @param result[inout]      bloblist_t to update or NULL to alloc a new one
 *  @param copy               copy data if true, move data otherwise
 *  @param max_blob_size      reject if sum(blob.size) > max_blob_size
 *                            to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

bloblist_t *BlobList_to_bloblist(
        BlobList_t *list,
        bloblist_t *result,
        bool copy,
        size_t max_blob_size
    );


/**
 *  <!--       ASN1Message_from_message()       -->
 *  
 *  @brief Convert message into ASN.1 ASN1Message_t
 *  
 *  @param msg[in]            message to convert
 *  @param result[inout]      ASN1Message_t to update or NULL to alloc a new one
 *  @param copy               copy data if true, move data otherwise
 *  @param max_blob_size      reject if sum(blob.size) > max_blob_size
 *                            to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

ASN1Message_t *ASN1Message_from_message(
        message *msg,
        ASN1Message_t *result,
        bool copy,
        size_t max_blob_size
    );


/**
 *  <!--       ASN1Message_to_message()       -->
 *  
 *  @brief Convert ASN.1 ASN1Message_t to message
 *  
 *  @param msg[in]            ASN.1 ASN1Message_t to convert
 *  @param result[inout]      message to update or NULL to alloc a new one
 *  @param copy               copy data if true, move data otherwise
 *  @param max_blob_size      reject if sum(blob.size) > max_blob_size
 *                            to disable set to 0
 *  
 *  @retval pointer to updated or allocated result
 *  
 *  @warning if a new struct is allocated, the ownership goes to the caller
 *  
 */

message *ASN1Message_to_message(
        ASN1Message_t *msg,
        message *result,
        bool copy,
        size_t max_blob_size
    );


#ifdef __cplusplus
}
#endif

#endif
