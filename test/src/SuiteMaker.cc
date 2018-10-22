// This file is under GNU General Public License 3.0
// see LICENSE.txt

//
// src/SuiteMaker.cc generated by gensuitemaker.py - changes may be overwritten. You've been warned!
//

#include <cpptest.h>
#include <cpptest-suite.h>
#include <memory>
#include <vector>
#include "SuiteMaker.h"

// Begin where we generate stuff
#include "DecorateTests.h"
#include "UserIdCollisionTests.h"
#include "ReencryptPlusExtraKeysTests.h"
#include "BlacklistTests.h"
#include "AppleMailTests.h"
#include "MessageTwoPointOhTests.h"
#include "IdentityListTests.h"
#include "I18nTests.h"
#include "Engine463Tests.h"
#include "DecryptAttachPrivateKeyUntrustedTests.h"
#include "BCCTests.h"
#include "LeastColorGroupTests.h"
#include "BlacklistAcceptNewKeyTests.h"
#include "MessageApiTests.h"
#include "StringlistTests.h"
#include "StringpairListTests.h"
#include "TrustManipulationTests.h"
#include "SyncTests.h"
#include "EncryptAttachPrivateKeyTests.h"
#include "BloblistTests.h"
#include "KeyResetMessageTests.h"
#include "SequenceTests.h"
#include "TrustwordsTests.h"
#include "RevokeRegenAttachTests.h"
#include "EncryptMissingPrivateKeyTests.h"
#include "PepSubjectReceivedTests.h"
#include "KeyeditTests.h"
#include "MapAsn1Tests.h"
#include "PgpBinaryTests.h"
#include "DecryptAttachPrivateKeyTrustedTests.h"
#include "MessageNullFromTests.h"
#include "MimeTests.h"
#include "PgpListKeysTests.h"
#include "NewUpdateIdAndMyselfTests.h"
#include "EncryptForIdentityTests.h"
#include "CrashdumpTests.h"
#include "CaseAndDotAddressTests.h"
#include "LeastCommonDenomColorTests.h"
#include "ExternalRevokeTests.h"
#include "UserIDAliasTests.h"


const char* SuiteMaker::all_suites[] = {
    "DecorateTests",
    "UserIdCollisionTests",
    "ReencryptPlusExtraKeysTests",
    "BlacklistTests",
    "AppleMailTests",
    "MessageTwoPointOhTests",
    "IdentityListTests",
    "I18nTests",
    "Engine463Tests",
    "DecryptAttachPrivateKeyUntrustedTests",
    "BCCTests",
    "LeastColorGroupTests",
    "BlacklistAcceptNewKeyTests",
    "MessageApiTests",
    "StringlistTests",
    "StringpairListTests",
    "TrustManipulationTests",
    "SyncTests",
    "EncryptAttachPrivateKeyTests",
    "BloblistTests",
    "KeyResetMessageTests",
    "SequenceTests",
    "TrustwordsTests",
    "RevokeRegenAttachTests",
    "EncryptMissingPrivateKeyTests",
    "PepSubjectReceivedTests",
    "KeyeditTests",
    "MapAsn1Tests",
    "PgpBinaryTests",
    "DecryptAttachPrivateKeyTrustedTests",
    "MessageNullFromTests",
    "MimeTests",
    "PgpListKeysTests",
    "NewUpdateIdAndMyselfTests",
    "EncryptForIdentityTests",
    "CrashdumpTests",
    "CaseAndDotAddressTests",
    "LeastCommonDenomColorTests",
    "ExternalRevokeTests",
    "UserIDAliasTests",
};

// This file is generated, so magic constants are ok.
int SuiteMaker::num_suites = 40;

void SuiteMaker::suitemaker_build(const char* test_class_name, const char* test_home, Test::Suite** test_suite) {
    if (strcmp(test_class_name, "DecorateTests") == 0)
        *test_suite = new DecorateTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "UserIdCollisionTests") == 0)
        *test_suite = new UserIdCollisionTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "ReencryptPlusExtraKeysTests") == 0)
        *test_suite = new ReencryptPlusExtraKeysTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BlacklistTests") == 0)
        *test_suite = new BlacklistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "AppleMailTests") == 0)
        *test_suite = new AppleMailTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MessageTwoPointOhTests") == 0)
        *test_suite = new MessageTwoPointOhTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "IdentityListTests") == 0)
        *test_suite = new IdentityListTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "I18nTests") == 0)
        *test_suite = new I18nTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "Engine463Tests") == 0)
        *test_suite = new Engine463Tests(test_class_name, test_home);
    else if (strcmp(test_class_name, "DecryptAttachPrivateKeyUntrustedTests") == 0)
        *test_suite = new DecryptAttachPrivateKeyUntrustedTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BCCTests") == 0)
        *test_suite = new BCCTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "LeastColorGroupTests") == 0)
        *test_suite = new LeastColorGroupTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BlacklistAcceptNewKeyTests") == 0)
        *test_suite = new BlacklistAcceptNewKeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MessageApiTests") == 0)
        *test_suite = new MessageApiTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "StringlistTests") == 0)
        *test_suite = new StringlistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "StringpairListTests") == 0)
        *test_suite = new StringpairListTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "TrustManipulationTests") == 0)
        *test_suite = new TrustManipulationTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SyncTests") == 0)
        *test_suite = new SyncTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EncryptAttachPrivateKeyTests") == 0)
        *test_suite = new EncryptAttachPrivateKeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "BloblistTests") == 0)
        *test_suite = new BloblistTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "KeyResetMessageTests") == 0)
        *test_suite = new KeyResetMessageTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "SequenceTests") == 0)
        *test_suite = new SequenceTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "TrustwordsTests") == 0)
        *test_suite = new TrustwordsTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "RevokeRegenAttachTests") == 0)
        *test_suite = new RevokeRegenAttachTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EncryptMissingPrivateKeyTests") == 0)
        *test_suite = new EncryptMissingPrivateKeyTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "PepSubjectReceivedTests") == 0)
        *test_suite = new PepSubjectReceivedTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "KeyeditTests") == 0)
        *test_suite = new KeyeditTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MapAsn1Tests") == 0)
        *test_suite = new MapAsn1Tests(test_class_name, test_home);
    else if (strcmp(test_class_name, "PgpBinaryTests") == 0)
        *test_suite = new PgpBinaryTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "DecryptAttachPrivateKeyTrustedTests") == 0)
        *test_suite = new DecryptAttachPrivateKeyTrustedTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MessageNullFromTests") == 0)
        *test_suite = new MessageNullFromTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "MimeTests") == 0)
        *test_suite = new MimeTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "PgpListKeysTests") == 0)
        *test_suite = new PgpListKeysTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "NewUpdateIdAndMyselfTests") == 0)
        *test_suite = new NewUpdateIdAndMyselfTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "EncryptForIdentityTests") == 0)
        *test_suite = new EncryptForIdentityTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "CrashdumpTests") == 0)
        *test_suite = new CrashdumpTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "CaseAndDotAddressTests") == 0)
        *test_suite = new CaseAndDotAddressTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "LeastCommonDenomColorTests") == 0)
        *test_suite = new LeastCommonDenomColorTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "ExternalRevokeTests") == 0)
        *test_suite = new ExternalRevokeTests(test_class_name, test_home);
    else if (strcmp(test_class_name, "UserIDAliasTests") == 0)
        *test_suite = new UserIDAliasTests(test_class_name, test_home);
}

void SuiteMaker::suitemaker_buildlist(const char** test_class_names, int num_to_run, const char* test_home, std::vector<Test::Suite*>& test_suites) {
    for (int i = 0; i < num_to_run; i++) {
        Test::Suite* suite = NULL;
        SuiteMaker::suitemaker_build(test_class_names[i], test_home, &suite);
        if (!suite)
            throw std::runtime_error("Could not create a test suite instance."); // FIXME, better error, cleanup, obviously
        test_suites.push_back(suite);
    }
}
void SuiteMaker::suitemaker_buildall(const char* test_home, std::vector<Test::Suite*>& test_suites) {
    SuiteMaker::suitemaker_buildlist(SuiteMaker::all_suites, SuiteMaker::num_suites, test_home, test_suites);
}

