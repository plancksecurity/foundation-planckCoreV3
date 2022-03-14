/**
 * @internal
 * @file    base64.c 
 * @brief   Convert base64 to a binary blob - this is the implementation of 
 *          a convenience function used mainly to convert keys which are
 *          base64 rather than radix64 (i.e. PGP armoured) encoded
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "platform.h"
#include "base64.h"

/**
 *  @internal
 * <!-- translate_char_to_bits() -->
 * @brief convert ascii value to corresponding base64 digit value
 * @param[in] input char to translate
 * @retval base64 value
 * @retval -1 if char is not a base64 encoding char.
 */
static char translate_char_to_bits(char input) {
    if (input >= 65 && input <= 90)
        return input - 65;
    if (input >= 97 && input <= 122)
        return input - 71; // 97 - 26
    if (input >= 48 && input <= 57)
        return input + 4; // 52 - 48
    if (input == '+')
        return 62;
    if (input == '/')
        return 63;
    if (input == ' ' || input == '\r' || input == '\n')
        return 127;
    return -1;    
}

/**
 *  @internal
 *  
 *  <!--       _is_whitespace()       -->
 *  
 *  @brief      checks if a character is a whitespace character
 *              end returns true if so, false otherwise
 *  
 *  @param[in]  in      char to be checked  
 *  @retval     bool    true if whitespace, false otherwise
 *  
 */
static bool _is_whitespace(const char in) {
    switch (in) {
        case ' ':
        case '\r':
        case '\t':
        case '\n':
            return true;
        default:
            return false;
    }        
}

/**
 *  @internal
 *  
 *  <!--       subtract_whitespace()       -->
 *  
 *  @brief      returns the length of the C string
 *              not counting whitespaces
 *  
 *  @param[in]  *input      C string
 *  @param[in]  length      length of the C string
 *  @retval     size_t      actual size of string without whitespaces 
 *  
 */
static size_t subtract_whitespace(const char* input, int length) {
    size_t actual_size = length;
    int i;
    const char* curr = input;
    for (i = 0; i < length; i++, curr++) {
        if (_is_whitespace(*curr))
            actual_size--;
    }
    return actual_size;
}
    
/**
 *  @internal
 *  
 *  <!--       trim_end()       -->
 *  
 *  @brief      determine length of C string without
 *              trailing whitespace characters
 *  
 *  @param[in]   *input     C string to check
 *  @param[out]  *length    returns the resulting lenght
 *  
 */
static void trim_end(const char* input, int* length) {
    const char* end = input + *length;
    
    int start_length = *length;
    
    int i;
    
    for (i = 0; i < start_length; i++) {
        if (!_is_whitespace(*(--end)))
            break;
        (*length) = (*length) - 1;        
    }
}    
    
/**
 *  @internal
 *  
 *  <!--       next_char()       -->
 *  
 *  @brief    returns the next non-whitespace character in a C string
 *  
 *  @param[in]  **input_ptr     pointer to C string
 *  @param[in]  *end            pointer to last char of input string
 *
 *  @retval     char            next non-whitespace character
 *  
 */
char next_char(const char** input_ptr, const char* end) {
    const char* input = *input_ptr;
    char this_ch = 0;
    
    while (input < end) {
        this_ch = *input++;
        if (!this_ch)
            return 0;
        if (_is_whitespace(this_ch))
            continue;
        break;    
    }
    
    *input_ptr = input;
    return this_ch;
}

/*
 *  @internal
 *  
 *  <!--       base64_str_to_binary_blob()       -->
 *  documented in base64.h  
 */
bloblist_t* base64_str_to_binary_blob(const char* input, int length) {
    if (length == 0)
        return NULL;
    
    trim_end(input, &length);
    
    void* blobby = NULL;
    
    const char* input_curr;
    input_curr = input;
    const char* input_end = input_curr + length;
    length = subtract_whitespace(input, length);
    size_t final_length = (length / 4) * 3;

    // padded -- FIXME: whitespace in between ==!!!!
    if (final_length && *(input_end - 1) == '=') {
        final_length -= 1;
        
        // if final length is now decreased by 1 and greater than 0,
        // we know there's a char at (input_end - 2).
        if (final_length && *(input_end - 2) == '=')
            final_length -=1;
    }
    else {
        // not padded
        int leftover = length % 4;
        switch (leftover) {
            case 0:
                break;
            case 2:
                final_length++;
                break;
            case 3:
                final_length+=2;
                break;
            default:
                return NULL;
        }
    }
    
    if (!final_length)
        goto pEp_error;
        
    blobby = calloc(final_length, 1);
    char* blobby_curr = (char*)blobby;

    // if the last 1 or 2 bytes are padded, we do those after
    size_t number_of_rounds = final_length / 3;
    
    unsigned int cycle;
    
    // full 3-byte rounds
    for (cycle = 0; cycle < number_of_rounds; cycle++) {
        char byte_array[] = {0,0,0};
        char in_val = next_char(&input_curr, input_end);
        if (in_val == 0)
            goto pEp_error; // can ALSO happen when input_curr == input_end,
                            // which simply shouldn't happen, since we're
                            // interating based on expected OUTPUT, not
                            // input.
                            
        char out_val = translate_char_to_bits(in_val);
        if (out_val > 63)
            goto pEp_error;
        
        byte_array[0] |= out_val << 2;

        in_val = next_char(&input_curr, input_end);
        if (in_val == 0)
            goto pEp_error;         
        out_val = translate_char_to_bits(in_val);
        if (out_val > 63)
            goto pEp_error;

        byte_array[0] |= out_val >> 4;
        byte_array[1] = out_val << 4;
        
        in_val = next_char(&input_curr, input_end);
        if (in_val == 0)
            goto pEp_error;         
        out_val = translate_char_to_bits(in_val);
        if (out_val > 63)
            goto pEp_error;
    
        byte_array[1] |= out_val >> 2;
        byte_array[2] = out_val << 6;

        in_val = next_char(&input_curr, input_end);
        if (in_val == 0)
            goto pEp_error;         
        out_val = translate_char_to_bits(in_val);
        if (out_val > 63)
            goto pEp_error;
        
        byte_array[2] |= out_val;
        
        // Now write everything to the blob
        *blobby_curr++ = byte_array[0];
        *blobby_curr++ = byte_array[1];
        *blobby_curr++ = byte_array[2];        
    }

    int last_bytes = final_length % 3;

    if (last_bytes != 0) {
        char byte_1 = 0;
        char byte_2 = 0;

        char in_val = next_char(&input_curr, input_end);
        if (in_val == 0)
            goto pEp_error;         
        char out_val = translate_char_to_bits(in_val);
        if (out_val > 63)
            goto pEp_error;
        byte_1 = out_val << 2;
        in_val = next_char(&input_curr, input_end);
        if (in_val == 0)
            goto pEp_error;         
        out_val = translate_char_to_bits(in_val);
        if (out_val > 63)
            goto pEp_error;
        byte_1 |= out_val >> 4;
        *blobby_curr++ = byte_1;                   
            
        if (last_bytes == 2) {
            byte_2 = out_val << 4;
            in_val = next_char(&input_curr, input_end);
            if (in_val == 0)
                goto pEp_error;         
            
            out_val = translate_char_to_bits(in_val);
            if (out_val > 63)
                goto pEp_error;
        
            byte_2 |= out_val >> 2;
            *blobby_curr++ = byte_2;
        }
    }
    
    return new_bloblist((char*)blobby, final_length, NULL, NULL);
            
pEp_error:
    free(blobby);
    return NULL;
}    
