#ifndef PEP_TEST_UTILS_H
#define PEP_TEST_UTILS_H

#include <string>
#include <stdlib.h>
#include <sys/stat.h>
#include <ftw.h>
#include <iostream>
#include <vector>

#include "pEpEngine.h"
#include "message_api.h"
#include "aux_mime_msg.h"
#include "mime.h"

#include <gtest/gtest.h>

void test_init();

bool file_exists(std::string filename);
bool is_pEpmsg(const message *msg); // duplicates static func in message_api.c, fyi

#ifndef ASSERT_OK
#define ASSERT_OK ASSERT_EQ(status, PEP_STATUS_OK)
#endif

#ifndef ASSERT_NOTNULL
#define ASSERT_NOTNULL(X) ASSERT_NE((X), nullptr)
#endif

#ifndef ASSERT_NULL
#define ASSERT_NULL(X) ASSERT_EQ((X), nullptr)
#endif

// Makefile actually handles this - this is just to please IDE error indicators tbh
#ifndef GTEST_SUITE_SYM
#define GTEST_SUITE_SYM test_suite_name
#endif

extern std::string _main_test_home_dir;

#ifndef DEBUG_OUTPUT
extern std::ostream output_stream;
#else
#define output_stream std::cerr
#endif

class TestUtilsPreset {
public:

    class IdentityInfo {
    public:
        // instance stuff
        char* name;
        char* user_id;
        char* email;
        char* key_prefix;
        char* fpr;

        IdentityInfo(const char* name, const char* user_id, const char* email, const char* key_prefix, const char* fpr) {
            this->name = strdup(name);
            this->user_id = strdup(user_id);
            this->email = strdup(email);
            this->key_prefix = strdup(key_prefix);
            this->fpr = strdup(fpr);
        }
        ~IdentityInfo() {
            free(name);
            free(user_id);
            free(email);
            free(key_prefix);
            free(fpr);
        }
    };
    // static stuff


    typedef enum _ident_preset {
        ALICE       = 0,
        APPLE       = 1,
        BOB         = 2,
        CAROL       = 3,
        DAVE        = 4,
        ERIN        = 5,
        FRANK       = 6,
        GABRIELLE   = 7,
        JOHN        = 8,
        ALEX        = 9,
        ALEX_0      = 10,
        ALEX_1      = 11,
        ALEX_2      = 12,
        ALEX_3      = 13,
        ALEX_4      = 14,
        ALEX_5      = 15,
        ALEX_6A     = 16,
        ALEX_6B     = 17,
        ALEX_6C     = 18,
        ALEX_6D     = 19,
        BELLA       = 20,
        FENRIS      = 21,
        SERCULLEN   = 22,
        INQUISITOR  = 23,
        BERND       = 24
    } ident_preset;

    static PEP_STATUS set_up_preset(PEP_SESSION session,
                         ident_preset preset_name,
                         bool set_identity,
                         bool set_fpr,
                         bool set_pep,
                         bool trust,
                         bool set_own,
                         bool setup_private,
                         pEp_identity** ident);
private:
    static inline const IdentityInfo presets[] = {
                IdentityInfo("Alice Spivak Hyatt", "ALICE", "pep.test.alice@pep-project.org", "pep-test-alice-0x6FF00E97", "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97"),
                IdentityInfo("Apple of my Computer", "APPLE", "pep.test.apple@pep-project.org", "pep-test-apple-0x1CCBC7D7", "3D8D9423D03DDF61B60161150313D94A1CCBC7D7"),
                IdentityInfo("Bob Dog", "BOB", "pep.test.bob@pep-project.org", "pep-test-bob-0xC9C2EE39", "BFCDB7F301DEEEBBF947F29659BFF488C9C2EE39"),
                IdentityInfo("Carol Burnett", "CAROL", "pep-test-carol@pep-project.org", "pep-test-carol-0x42A85A42", "8DD4F5827B45839E9ACCA94687BDDFFB42A85A42"),
                IdentityInfo("The Hoff", "DAVE", "pep-test-dave@pep-project.org", "pep-test-dave-0xBB5BCCF6", "E8AC9779A2D13A15D8D55C84B049F489BB5BCCF6"),
                IdentityInfo("Erin Ireland", "ERIN", "pep-test-erin@pep-project.org", "pep-test-erin-0x9F8D7CBA", "1B0E197E8AE66277B8A024B9AEA69F509F8D7CBA"),
                IdentityInfo("Frank N. Furter", "FRANK", "pep-test-frank@pep-project.org", "pep-test-frank-0x9A7FC670", "B022B74476D8A8E1F01E55FBAB6972569A7FC670"),  // currently expired
                IdentityInfo("Gabrielle Gonzales", "GABI", "pep-test-gabrielle@pep-project.org", "pep-test-gabrielle-0xE203586C", "906C9B8349954E82C5623C3C8C541BD4E203586C"),
                IdentityInfo("John Denver", "JOHN", "pep.test.john@pep-project.org", "pep-test-john-0x70DCF575", "AA2E4BEB93E5FE33DEFD8BE1135CD6D170DCF575"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander@peptest.ch", "pep.test.alexander-0x26B54E4E", "3AD9F60FAEB22675DB873A1362D6981326B54E4E"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander0@darthmama.org", "pep.test.alexander0-0x3B7302DB", "F4598A17D4690EB3B5B0F6A344F04E963B7302DB"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander1@darthmama.org", "pep.test.alexander1-0x541260F6", "59AF4C51492283522F6904531C09730A541260F6"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander2@darthmama.org", "pep.test.alexander2-0xA6512F30", "46A994F19077C05610870273C4B8AB0BA6512F30"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander3@darthmama.org", "pep.test.alexander3-0x724B3975", "5F7076BBD92E14EA49F0DF7C2CE49419724B3975"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander4@darthmama.org", "pep.test.alexander4-0x844B9DCF", "E95FFF95B8E2FDD4A12C3374395F1485844B9DCF"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander5@darthmama.org", "pep.test.alexander5-0x0773CD29", "58BCC2BF2AE1E3C4FBEAB89AD7838ACA0773CD29"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0x0019697D", "74D79B4496E289BD8A71B70BA8E2C4530019697D"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0x503B14D8", "2E21325D202A44BFD9C607FCF095B202503B14D8"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0xA216E95A", "3C1E713D8519D7F907E3142D179EAA24A216E95A"),
                IdentityInfo("Alex Braithwaite", "ALEX", "pep.test.alexander6@darthmama.org", "pep.test.alexander6-0xBDA17020", "B4CE2F6947B6947C500F0687AEFDE530BDA17020"),
                IdentityInfo("Bella Cat", "BELLA", "pep.test.bella@peptest.ch", "pep.test.bella-0xAF516AAE", "5631BF1357326A02AA470EEEB815EF7FA4516AAE"),
                IdentityInfo("Fenris Leto Hawke", "FENRIS", "pep.test.fenris@thisstilldoesntwork.lu", "pep.test.fenris-0x4F3D2900", "0969FA229DF21C832A64A04711B1B9804F3D2900"),
                IdentityInfo("Cullen Rutherford", "CULLEN", "sercullen-test@darthmama.org", "sercullen-0x3CEAADED4", "1C9666D8B3E28F4AA3847DA89A6E75E3CEAADED4"),  // NB expired on purpose
                IdentityInfo("Inquisitor Claire Trevelyan", "INQUISITOR", "inquisitor@darthmama.org", "inquisitor-0xA4728718_renewed", "8E8D2381AE066ABE1FEE509821BA977CA4728718"),
                IdentityInfo("Bernd das Brot", "BERNDI", "bernd.das.brot@darthmama.org", "bernd.das.brot-0xCAFAA422", "F8CE0F7E24EB190A2FCBFD38D4B088A7CAFAA422")
    };
    static constexpr int PRESETS_LEN = sizeof(presets);
};

std::string get_main_test_home_dir();
std::string random_string( size_t length );

PEP_STATUS read_file_and_import_key(PEP_SESSION session, const char* fname);
PEP_STATUS set_up_ident_from_scratch(PEP_SESSION session, 
                                     const char* key_fname,
                                     const char* address,
                                     const char* fpr,
                                     const char* user_id,
                                     const char* username,
                                     pEp_identity** ret_ident,
                                     bool is_priv);

// string equality (case and non-case sensitive)
bool _streq(const char* str1, const char* str2);
bool _strceq(const char* str1, const char* str2);

// reads a whole file and returns it as std::string
// throws std::runtime_error() if the file cannot be read. Empty file is not an error.
std::string slurp(const std::string& filename);

// dumps char* to file
// throws std::runtime_error() if the file cannot be opened.
void dump_out(const char* filename, const char* outdata);

// Returns the string value of the input rating enum value. 
const char* tl_rating_string(PEP_rating rating);

// Returns the string value of the input comm_type enum value. 
const char* tl_ct_string(PEP_comm_type ct);

// Returns the string value of the input status enum value. 
const char* tl_status_string(PEP_STATUS status);

std::string tl_ident_flags_String(identity_flags_t fl);

// Grabs a new uuid for your randomish string needs.
char* get_new_uuid();

bool slurp_and_import_key(PEP_SESSION session, const char* key_filename);

bool slurp_message_and_import_key(PEP_SESSION session, const char* message_fname, std::string& message, const char* key_filename);

char* message_to_str(message* msg);
message* string_to_msg(std::string infile);

// For when you ONLY care about the message
PEP_STATUS vanilla_encrypt_and_write_to_file(PEP_SESSION session, message* msg, const char* filename);
PEP_STATUS vanilla_read_file_and_decrypt(PEP_SESSION session, message** msg, const char* filename);

int util_delete_filepath(const char *filepath, 
                         const struct stat *file_stat, 
                         int ftw_info, 
                         struct FTW * ftw_struct);
                         
class NullBuffer : public std::streambuf {
    public:
        int overflow(int c);
};                         
                         
PEP_STATUS config_valid_passphrase(PEP_SESSION session, const char* fpr, std::vector<std::string> passphrases);
PEP_STATUS set_default_fpr_for_test(PEP_SESSION session, pEp_identity* ident, bool unconditional);
PEP_STATUS set_fpr_preserve_ident(PEP_SESSION session, const pEp_identity* ident, const char* fpr, bool valid_only);

void print_mail(message* msg);

#ifndef ENIGMAIL_MAY_USE_THIS

// MIME_decrypt_message() - decrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to decrypt
//      size (in)               size of mime text to decode (in order to decrypt)
//      mime_plaintext (out)    decrypted, encoded message
//      keylist (inout)         in: stringlist with additional keyids for reencryption if needed
//                                  (will be freed and replaced with output keylist)
//                              out: stringlist with keyids
//      rating (out)            rating for the message
//      flags (inout)           flags to signal special decryption features (see below)
//      modified_src (out)      modified source string, if decrypt had reason to change it
//
//  return value:
//      decrypt status          if everything worked with MIME encode/decode, 
//                              the status of the decryption is returned 
//                              (PEP_STATUS_OK or decryption error status)
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  flag values:
//      in:
//          PEP_decrypt_flag_untrusted_server
//              used to signal that decrypt function should engage in behaviour
//              specified for when the server storing the source is untrusted.
//      out:
//          PEP_decrypt_flag_own_private_key
//              private key was imported for one of our addresses (NOT trusted
//              or set to be used - handshake/trust is required for that)
//          PEP_decrypt_flag_src_modified
//              indicates that the modified_src field should contain a modified
//              version of the source, at the moment always as a result of the
//              input flags. 
//          PEP_decrypt_flag_consume
//              used by sync 
//          PEP_decrypt_flag_ignore
//              used by sync 
// 
//  caveat:
//      the decrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
PEP_STATUS MIME_decrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    char** mime_plaintext,
    stringlist_t **keylist,
    PEP_rating *rating,
    PEP_decrypt_flags_t *flags,
    char** modified_src
);

// MIME_encrypt_message() - encrypt a MIME message, with MIME output
//
//  parameters:
//      session (in)            session handle
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
//      extra (in)              extra keys for encryption
//      mime_ciphertext (out)   encrypted, encoded message
//      enc_format (in)         encrypted format
//      flags (in)              flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the encrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
DYNAMIC_API PEP_STATUS MIME_encrypt_message(
    PEP_SESSION session,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);


// MIME_encrypt_message_for_self() - encrypt MIME message for user's identity only,
//                              ignoring recipients and other identities from
//                              the message, with MIME output
//  parameters:
//      session (in)            session handle
//      target_id (in)          self identity this message should be encrypted for
//      mimetext (in)           MIME encoded text to encrypt
//      size (in)               size of input mime text
//      extra (in)              extra keys for encryption
//      mime_ciphertext (out)   encrypted, encoded message
//      enc_format (in)         encrypted format
//      flags (in)              flags to set special encryption features
//
//  return value:
//      PEP_STATUS_OK           if everything worked
//      PEP_BUFFER_TOO_SMALL    if encoded message size is too big to handle
//      PEP_CANNOT_CREATE_TEMP_FILE
//                              if there are issues with temp files; in
//                              this case errno will contain the underlying
//                              error
//      PEP_OUT_OF_MEMORY       if not enough memory could be allocated
//
//  caveat:
//      the encrypted, encoded mime text will go to the ownership of the caller; mimetext
//      will remain in the ownership of the caller
PEP_STATUS MIME_encrypt_message_for_self(
    PEP_SESSION session,
    pEp_identity* target_id,
    const char *mimetext,
    size_t size,
    stringlist_t* extra,
    char** mime_ciphertext,
    PEP_enc_format enc_format,
    PEP_encrypt_flags_t flags
);

#endif
#endif
