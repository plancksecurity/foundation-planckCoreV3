#include "cryptotech.h"

#include <stdlib.h>
#include <memory.h>
#include <assert.h>

PEP_STATUS init_cryptotech(PEP_cryptotech_t *cryptotech)
{
    assert(PEP_crypt__count == 2);
    memset(cryptotech, 0, sizeof(PEP_cryptotech_t) * PEP_crypt__count);

    cryptotech[0].id = PEP_crypt_none;

    cryptotech[1].id = PEP_crypt_OpenPGP;
    cryptotech[1].decrypt_and_verify = decrypt_and_verify;
    cryptotech[1].encrypt_and_sign = encrypt_and_sign;
    cryptotech[1].verify_text = verify_text;

    return PEP_STATUS_OK;
}
