/**
 * @file    pEp_rmd160.h
 * @brief   RMD160 implementation from libTomCrypt: prototype
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_RMD160_H_
#define PEP_RMD160_H_

/**
 *  <!--       pEp_rmd160()       -->
 *
 *  @brief Compute a RIPEMD-160 hash.
 *         This is a convenience wrapper for pEp, built upon the libTomCrypt
 *         implementation.
 *
 *  @param[out]  out         the output bytes, allocated by the caller.  The
 *                           pointer must refer an array of at least 16 bytes.
 *  @param[in]   in          the input
 *  @param[in]   in_byte_no  the input length in bytes
 */
void pEp_rmd160(unsigned char *out, const unsigned char *in, size_t in_byte_no);

#endif // PEP_RMD160_H_
