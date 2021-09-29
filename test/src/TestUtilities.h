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
#include "mime.h"
#include "status_to_string.h"

#include <gtest/gtest.h>

std::string get_main_test_home_dir();
void test_init();
bool file_exists(std::string filename);
bool is_pEpmsg(const message *msg); // duplicates static func in message_api.c, fyi
int util_delete_filepath(const char *filepath,
                         const struct stat *file_stat,
                         int ftw_info,
                         struct FTW * ftw_struct);

// string equality (case and non-case sensitive)
bool _streq(const char* str1, const char* str2);
bool _strceq(const char* str1, const char* str2);

// Generate random ASCII string of a certain length
std::string random_string( size_t length );
// Grabs a new uuid for your randomish string needs.
char* get_new_uuid();

/************************************************************************************
 * Expansion of googletest ASSERT defines
 */

#ifndef ASSERT_OK
#define ASSERT_OK                                             \
    do {                                                      \
        if (status != PEP_STATUS_OK)                          \
            std::cout << "status is " << status << " ("       \
                      << pEp_status_to_string(status) << ")"  \
                      << std::endl;                           \
        ASSERT_EQ(status, PEP_STATUS_OK);                     \
    } while (false)
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

/************************************************************************************
 * This is a cleanup of some preset functions we had set up before. It's still clunky, but
 * can be used as a way to avoid code duplication and have some standard identities with
 * which we have some already set up keys, etc. This could be done way better, frankly, but
 * taking the time to refactor right now isn't possible.
 */
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
        BOB2        = 3,
        CAROL       = 4,
        DAVE        = 5,
        ERIN        = 6,
        FRANK       = 7,
        GABRIELLE   = 8,
        JOHN        = 9,
        ALEX        = 10,
        ALEX_0      = 11,
        ALEX_1      = 12,
        ALEX_2      = 13,
        ALEX_3      = 14,
        ALEX_4      = 15,
        ALEX_5      = 16,
        ALEX_6A     = 17,
        ALEX_6B     = 18,
        ALEX_6C     = 19,
        ALEX_6D     = 20,
        BELLA       = 21,
        FENRIS      = 22,
        SERCULLEN   = 23,
        INQUISITOR  = 24,
        BERND       = 25,
        SYLVIA      = 26,
        SYLVIA2     = 27
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

    static PEP_STATUS import_preset_key(PEP_SESSION session,
                                    ident_preset preset_name,
                                    bool private_also);

    static pEp_identity* generateAndSetOpenPGPPartnerIdentity(PEP_SESSION session,
                                                              ident_preset preset_name,
                                                              bool set_fpr,
                                                              bool trust);
    static pEp_identity* generateAndSetpEpPartnerIdentity(PEP_SESSION session,
                                                          ident_preset preset_name,
                                                          bool set_fpr,
                                                          bool trust);


    static pEp_identity* generateAndSetPrivateIdentity(PEP_SESSION session,
                                                       ident_preset preset_name);

    static pEp_identity* generateOnlyPrivateIdentity(PEP_SESSION session,
                                                     ident_preset preset_name);

    static pEp_identity* generateOnlyPartnerIdentity(PEP_SESSION session,
                                                     ident_preset preset_name);

    static pEp_identity* generateOnlyPrivateIdentityGrabFPR(PEP_SESSION session,
                                                            ident_preset preset_name);

    static pEp_identity* generateOnlyPartnerIdentityGrabFPR(PEP_SESSION session,
                                                            ident_preset preset_name);
    static const IdentityInfo presets[];
};

// FIXME: Refactor tests from above
PEP_STATUS set_up_ident_from_scratch(PEP_SESSION session, 
                                     const char* key_fname,
                                     const char* address,
                                     const char* fpr,
                                     const char* user_id,
                                     const char* username,
                                     pEp_identity** ret_ident,
                                     bool is_priv);


// reads a whole file and returns it as std::string
// throws std::runtime_error() if the file cannot be read. Empty file is not an error.
std::string slurp(const std::string& filename);
// dumps char* to file
// throws std::runtime_error() if the file cannot be opened.
void dump_out(const char* filename, const char* outdata);
void print_mail(message* msg);

// Read in a keyfile and import it
// FIXME: why do we have two of these? Is it just the status returns?
PEP_STATUS read_file_and_import_key(PEP_SESSION session, const char* fname);
bool slurp_and_import_key(PEP_SESSION session, const char* key_filename);
bool slurp_message_and_import_key(PEP_SESSION session, const char* message_fname, std::string& message, const char* key_filename);
message* slurp_message_file_into_struct(std::string infile, PEP_msg_direction direction=PEP_dir_incoming);

void wipe_message_ptr(message** msg_ptr);

// For when you ONLY care about the message
PEP_STATUS vanilla_encrypt_and_write_to_file(PEP_SESSION session, message* msg, const char* filename, PEP_encrypt_flags_t flags = 0);
PEP_STATUS vanilla_read_file_and_decrypt(PEP_SESSION session, message** msg, const char* filename);
PEP_STATUS vanilla_read_file_and_decrypt_with_rating(PEP_SESSION session, message** msg, const char* filename, PEP_rating* rating);

PEP_STATUS config_valid_passphrase(PEP_SESSION session, const char* fpr, std::vector<std::string> passphrases);
PEP_STATUS set_default_fpr_for_test(PEP_SESSION session, pEp_identity* ident, bool unconditional);
PEP_STATUS set_fpr_preserve_ident(PEP_SESSION session, const pEp_identity* ident, const char* fpr, bool valid_only);

// Returns the string value of the input rating enum value. 
const char* tl_rating_string(PEP_rating rating);
// Returns the string value of the input comm_type enum value. 
const char* tl_ct_string(PEP_comm_type ct);
// Returns the string value of the input status enum value. 
const char* tl_status_string(PEP_STATUS status);
// Returns the string value of identity flags
std::string tl_ident_flags_String(identity_flags_t fl);

char* message_to_str(message* msg);
message* string_to_msg(std::string infile);

/************************************************************************************
 * We try not to use cout / cerr explicitly unless we set the compile option. This
 * is a null error stream that can be used to reduce spam and is set by default.
 * Use -DDEBUG_OUTPUT in compilation if you want output_stream to send output to stderr
 */
#ifndef DEBUG_OUTPUT
extern std::ostream output_stream;
#else
#define output_stream std::cerr
#endif

class NullBuffer : public std::streambuf {
    public:
        int overflow(int c);
};

#endif
