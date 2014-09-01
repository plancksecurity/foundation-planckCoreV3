#include "cryptotech.h"

#ifdef NO_GPG
#include "pgp_netpgp.h"
#else
#include "pgp_gpg.h"
#endif

#include <stdlib.h>
#include <memory.h>
#include <assert.h>

PEP_STATUS init_cryptotech(PEP_cryptotech_t *cryptotech)
{
    assert(PEP_crypt__count == 2);
    memset(cryptotech, 0, sizeof(PEP_cryptotech_t) * PEP_crypt__count);

    cryptotech[0].id = PEP_crypt_none;
    cryptotech[0].unconfirmed_comm_type = PEP_ct_no_encryption;
    cryptotech[0].confirmed_comm_type = PEP_ct_no_encryption;

    cryptotech[1].id = PEP_crypt_OpenPGP;
    cryptotech[1].unconfirmed_comm_type = PEP_ct_OpenPGP_unconfirmed;
    cryptotech[1].confirmed_comm_type = PEP_ct_OpenPGP;
    cryptotech[1].decrypt_and_verify = pgp_decrypt_and_verify;
    cryptotech[1].encrypt_and_sign = pgp_encrypt_and_sign;
    cryptotech[1].verify_text = pgp_verify_text;
    cryptotech[1].delete_keypair = pgp_delete_keypair;
    cryptotech[1].export_key = pgp_export_key;
    cryptotech[1].find_keys = pgp_find_keys;
    cryptotech[1].generate_keypair = pgp_generate_keypair;
    cryptotech[1].get_key_rating = pgp_get_key_rating;
    cryptotech[1].import_key = pgp_import_key;
    cryptotech[1].recv_key = pgp_recv_key;
    cryptotech[1].send_key = pgp_send_key;

    return PEP_STATUS_OK;
}
