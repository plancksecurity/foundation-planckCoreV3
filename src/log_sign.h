/**
 * @file    log_sign.h
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef LOG_SIGN_H
#define LOG_SIGN_H

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C"
{
#endif

PEP_STATUS log_sign(
        PEP_SESSION session,
        const char *ptext,
        size_t psize,
        char **stext,
        size_t *ssize);

PEP_STATUS log_verify(
    PEP_SESSION session,
    const char *ptext,
    size_t psize,
    const char *stext,
    size_t ssize);

#ifdef __cplusplus
}
#endif

#endif
