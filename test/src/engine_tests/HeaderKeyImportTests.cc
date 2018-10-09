// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <string>
#include <cstring>

#include <cpptest.h>

#include "pEpEngine.h"
#include "bloblist.h"
#include "base64.h"

#include "test_util.h"
#include "EngineTestIndividualSuite.h"
#include "HeaderKeyImportTests.h"

using namespace std;

HeaderKeyImportTests::HeaderKeyImportTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_padded_2)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_unpadded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_unpadded_2)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded_1)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded_2)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded_1"),    
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded_2"),    
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_padded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_unpadded_1)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_padded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_unpadded_1)));                                                                      
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_leading_whitespace_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_leading_whitespace_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_padded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_unpadded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_trailing_whitespace_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_trailing_whitespace_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_round"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_round)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_padded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_padded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_padded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_padded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_unpadded_1"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_unpadded_1)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::base_64_kitchen_sink_unpadded_2"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::base_64_kitchen_sink_unpadded_2)));
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("HeaderKeyImportTests::check_header_key_import"),
                                                                      static_cast<Func>(&HeaderKeyImportTests::check_header_key_import)));                                                                  
}

bool HeaderKeyImportTests::verify_base_64_test(const char* input, const char* desired_output) {
    bloblist_t* blobby = NULL;
    bool retval = false;
    size_t desired_output_length = 0;
    const char* blobval;
    
    blobby = base64_str_to_binary_blob(input, strlen(input));    
    if (!blobby)
        goto pEp_free;

    blobval = blobby->value;
    
    // N.B. Actual output will NOT be null-terminated!!!!
    desired_output_length = strlen(desired_output);
    if (blobby->size != desired_output_length) 
        goto pEp_free;
        
    int i;
    for (i = 0; i < desired_output_length; i++) {
        if (*blobval++ != *desired_output++)
        goto pEp_free;
    }
    
    retval = true;    
    
pEp_free:
    free_bloblist(blobby);
    return retval;
}

void HeaderKeyImportTests::base_64_minimal_round() {
    TEST_ASSERT(verify_base_64_test("TWFu", "Man"));
}

void HeaderKeyImportTests::base_64_minimal_padded_1() {
    TEST_ASSERT(verify_base_64_test("TWE=", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_padded_2() {
    TEST_ASSERT(verify_base_64_test("TQ==", "M"));
}

void HeaderKeyImportTests::base_64_minimal_unpadded_1() {
    TEST_ASSERT(verify_base_64_test("TWE", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_unpadded_2() {
    TEST_ASSERT(verify_base_64_test("TQ", "M"));
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_round() {
    TEST_ASSERT(verify_base_64_test(" \tTWFu", "Man"));
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded_1() {
    TEST_ASSERT(verify_base_64_test(" TWE=", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_padded_2() {
    TEST_ASSERT(verify_base_64_test("\nTQ==", "M"));
}

void HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded_1() {
    TEST_ASSERT(verify_base_64_test("\n TWE", "Ma"));
}
void HeaderKeyImportTests::base_64_minimal_leading_whitespace_unpadded_2() {
    TEST_ASSERT(verify_base_64_test(" TQ", "M"));
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_round() {
    TEST_ASSERT(verify_base_64_test("TWFu ", "Man"));
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded_1() {
    TEST_ASSERT(verify_base_64_test("TWE=\n ", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_padded_2() {
    TEST_ASSERT(verify_base_64_test("TQ==                 \n \t", "M"));
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded_1() {
    TEST_ASSERT(verify_base_64_test("TWE           ", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_trailing_whitespace_unpadded_2() {
    TEST_ASSERT(verify_base_64_test("TQ\n", "M"));
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_round() {
    TEST_ASSERT(verify_base_64_test("T\nWF\nu", "Man"));
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded_1() {
    TEST_ASSERT(verify_base_64_test("T    W E =", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_padded_2() {
    TEST_ASSERT(verify_base_64_test("T  Q==", "M"));
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded_1() {
    TEST_ASSERT(verify_base_64_test("T\nWE", "Ma"));
}

void HeaderKeyImportTests::base_64_minimal_internal_whitespace_unpadded_2() {
    TEST_ASSERT(verify_base_64_test("T\r\nQ", "M"));
}

void HeaderKeyImportTests::base_64_round() {
    const char* input = "V2hlbiB0aGluZ3MgZ28gd3JvbmcsIGFzIHRoZX"
                        "kgdXN1YWxseSB3aWxsCkFuZCB5b3VyIGRhaWx5"
                        "IHJvYWQgc2VlbXMgYWxsIHVwaGlsbApXaGVuIG"
                        "Z1bmRzIGFyZSBsb3csIGFuZCBkZWJ0cyBhcmUg"
                        "aGlnaApZb3UgdHJ5IHRvIHNtaWxlLCBidXQgY2"
                        "FuIG9ubHkgY3J5CldoZW4geW91IHJlYWxseSBm"
                        "ZWVsIHlvdSdkIGxpa2UgdG8gcXVpdCwKRG9uJ3"
                        "QgcnVuIHRvIG1lLCBJIGRvbid0IGdpdmUgYSBI"
                        "SSBOT1RISU5HIFRPIFNFRSBIRVJFISEh";
    
    const char* output = "When things go wrong, as they usually will\n"
                         "And your daily road seems all uphill\n"
                         "When funds are low, and debts are high\n"
                         "You try to smile, but can only cry\n"
                         "When you really feel you'd like to quit,\n"
                         "Don't run to me, I don't give a HI NOTHING TO SEE HERE!!!";
    
    TEST_ASSERT(verify_base_64_test(input, output));
}

void HeaderKeyImportTests::base_64_padded_1() {
    const char* input =
        "U2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4=";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";
    TEST_ASSERT(verify_base_64_test(input, output));
}

void HeaderKeyImportTests::base_64_padded_2() {
    const char* input = 
        "V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg==";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";
    TEST_ASSERT(verify_base_64_test(input, output));
    
}

void HeaderKeyImportTests::base_64_unpadded_1() {
    const char* input =
        "U2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4=";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";
    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_unpadded_2() {
    const char* input =
        "V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_leading_whitespace_round() {
    const char* input = "\r\nV2hlbiB0aGluZ3MgZ28gd3JvbmcsIGFzIHRoZX"
                        "kgdXN1YWxseSB3aWxsCkFuZCB5b3VyIGRhaWx5"
                        "IHJvYWQgc2VlbXMgYWxsIHVwaGlsbApXaGVuIG"
                        "Z1bmRzIGFyZSBsb3csIGFuZCBkZWJ0cyBhcmUg"
                        "aGlnaApZb3UgdHJ5IHRvIHNtaWxlLCBidXQgY2"
                        "FuIG9ubHkgY3J5CldoZW4geW91IHJlYWxseSBm"
                        "ZWVsIHlvdSdkIGxpa2UgdG8gcXVpdCwKRG9uJ3"
                        "QgcnVuIHRvIG1lLCBJIGRvbid0IGdpdmUgYSBI"
                        "SSBOT1RISU5HIFRPIFNFRSBIRVJFISEh";
    
    const char* output = "When things go wrong, as they usually will\n"
                         "And your daily road seems all uphill\n"
                         "When funds are low, and debts are high\n"
                         "You try to smile, but can only cry\n"
                         "When you really feel you'd like to quit,\n"
                         "Don't run to me, I don't give a HI NOTHING TO SEE HERE!!!";
    
    TEST_ASSERT(verify_base_64_test(input, output));
}

void HeaderKeyImportTests::base_64_leading_whitespace_padded_1() {
    const char* input =
        "\tU2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4=";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";
        
    TEST_ASSERT(verify_base_64_test(input, output));
        
}

void HeaderKeyImportTests::base_64_leading_whitespace_padded_2() {
    const char* input = 
        " V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg==";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";
        
    TEST_ASSERT(verify_base_64_test(input, output));
        
}

void HeaderKeyImportTests::base_64_leading_whitespace_unpadded_1() {
    const char* input =
        "\n\nU2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_leading_whitespace_unpadded_2() {
    const char* input = 
        "   V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_trailing_whitespace_round() {
    const char* input = "V2hlbiB0aGluZ3MgZ28gd3JvbmcsIGFzIHRoZX"
                        "kgdXN1YWxseSB3aWxsCkFuZCB5b3VyIGRhaWx5"
                        "IHJvYWQgc2VlbXMgYWxsIHVwaGlsbApXaGVuIG"
                        "Z1bmRzIGFyZSBsb3csIGFuZCBkZWJ0cyBhcmUg"
                        "aGlnaApZb3UgdHJ5IHRvIHNtaWxlLCBidXQgY2"
                        "FuIG9ubHkgY3J5CldoZW4geW91IHJlYWxseSBm"
                        "ZWVsIHlvdSdkIGxpa2UgdG8gcXVpdCwKRG9uJ3"
                        "QgcnVuIHRvIG1lLCBJIGRvbid0IGdpdmUgYSBI"
                        "SSBOT1RISU5HIFRPIFNFRSBIRVJFISEh\n";
    
    const char* output = "When things go wrong, as they usually will\n"
                         "And your daily road seems all uphill\n"
                         "When funds are low, and debts are high\n"
                         "You try to smile, but can only cry\n"
                         "When you really feel you'd like to quit,\n"
                         "Don't run to me, I don't give a HI NOTHING TO SEE HERE!!!";
    
    TEST_ASSERT(verify_base_64_test(input, output));
}

void HeaderKeyImportTests::base_64_trailing_whitespace_padded_1() {
    const char* input =
        "U2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4=   \n";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_trailing_whitespace_padded_2() {
    const char* input = 
        "V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg==         \n";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_trailing_whitespace_unpadded_1() {
    const char* input =
        "U2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4   \n";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_trailing_whitespace_unpadded_2() {
    const char* input = 
        "V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg\r\n";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_kitchen_sink_round() {
    const char* input = "\r\nV2hlbiB0aGluZ3MgZ28gd3JvbmcsIGFzIHRoZX\n"
                        "kgdXN1YWxseSB3aWxsCkFuZCB5b3VyIGRhaWx5\n"
                        "IHJvYWQgc2VlbXMgYWxsIHVwaGlsbApXaGVuIG\n"
                        "Z1bmRzIGFyZSBsb3csIGFuZCBkZWJ0cyBhcmUg\n"
                        "aGlnaApZb3UgdHJ5IHRvIHNtaWxlLCBidXQgY2\n"
                        "FuIG9ubHkgY3J5CldoZW4geW91IHJlYWxseSBm\n"
                        "ZWVsIHlvdSdkIGxpa2UgdG8gcXVpdCwKRG9uJ3\n"
                        "QgcnVuIHRvIG1lLCBJIGRvbid0IGdpdmUgYSBI\n"
                        "SSBOT1RISU5HIFRPIFNFRSBIRVJFISEh\r\n";
    
    const char* output = "When things go wrong, as they usually will\n"
                         "And your daily road seems all uphill\n"
                         "When funds are low, and debts are high\n"
                         "You try to smile, but can only cry\n"
                         "When you really feel you'd like to quit,\n"
                         "Don't run to me, I don't give a HI NOTHING TO SEE HERE!!!";
    
    TEST_ASSERT(verify_base_64_test(input, output));
}

void HeaderKeyImportTests::base_64_kitchen_sink_padded_1() {
    const char* input =
        "\r\nU2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg\n"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg\n"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu\n"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4=   \n";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_kitchen_sink_padded_2() {
    const char* input = 
        "                                                                                                 V2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg\n"
        "dGhlIEFyaXNob2s gcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg\n"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg\n"
        "ZW5vdWdoIGRvaW5n IHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz\n"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg\n"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyB\tjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu\r\n"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g\n"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg\n"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp\n"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv\n"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbm cgYXQ/IExvb255LiBZZWFo\n"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4\n\n\ngQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs\n"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv\n"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl\n"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg==\n\n\n\n  \t";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_kitchen_sink_unpadded_1() {
    const char* input =
        "\r\nU2ludGVya2xhYXMgS2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kg\n"
        "d2F0IGluIG3igJluIGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4KU2ludGVya2xhYXMg\n"
        "S2Fwb2VudGplLApHb29pIHdhdCBpbiBt4oCZbiBzY2hvZW50amUsCkdvb2kgd2F0IGluIG3igJlu\n"
        "IGxhYXJzamUuCkRhbmsgdSwgU2ludGVya2xhYXNqZS4   \n";
    
    const char* output =
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.\n"
        "Sinterklaas Kapoentje,\n"
        "Gooi wat in m’n schoentje,\n"
        "Gooi wat in m’n laarsje.\n"
        "Dank u, Sinterklaasje.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::base_64_kitchen_sink_unpadded_2() {
    const char* input = 
        "\r\n\r\n\r\nV2VsbCwgdGhhdCB3YXMgYSBtZXNzLiBCZXR0ZXIgZ2V0IHRoaW5ncyBpbiBvcmRlciBiZWZvcmUg\r\n"
        "dGhlIEFyaXNob2sgcmVzcG9uZHMuIENhbid0IGJlIGdvb2QuIFRoZSB2aXNjb3VudCdzIHNvbiwg\r\n"
        "UXVuYXJpIGluIHRoZSBDaGFudHJ5LiBCZXQgaXQncyBnb2luZyB0byByYWluLCB0b28uIEhhcmQg\r\n"
        "ZW5vdWdoIGRvaW5nIHRoaXMgd2l0aG91dCBzb2FraW5nIG15IGhpZGVzLiBUaGlydHkgcG91bmRz\r\n"
        "IG9mIHdhdGVyIGFuZCBpdCdzIGEgbWFyY2ggd2l0aCBubyByYXRpb25zLiBXaGVuIHdhcyB0aGUg\r\n"
        "bGFzdCB0aW1lIEkgYXRlPyBXaG8ncyBjb29raW5nIHRvbmlnaHQ/IFNhbmRhbD8gTWFrZXIuIEVu\r\n"
        "Y2hhbnRtZW50IHNvdXAgYWdhaW4uIFRodW1iIHJpZ2h0IGluIHRoZSBib3dsIGxhc3QgdGltZS4g\r\n"
        "SGlzIGVuY2hhbnRpbmcgaGFuZCwgdG9vLiBZZWFoLCBJIHNhdyB5b3UsIHlvdSBzcXVpcnJlbHkg\r\n"
        "bGl0dGxlIGtub3QtaGVhZC4gRGlkIEkgbG9jayBteSBjaGFtYmVycz8gSSdsbCBiZXQgaGUncyBp\r\n"
        "biB0aGVyZSBub3cuIFVnaC4gVGhhdCBndXkgbG9va2luZyBhdCBtZT8gVGhlcmUncyBhIGxvdCBv\r\n"
        "ZiBpbGxuZXNzIGluIHRoaXMgY2l0eS4gV2hhdCdzIGhlIGxvb2tpbmcgYXQ/IExvb255LiBZZWFo\r\n"
        "LCB0aGF0J3MgaXQsIGtlZXAgd2Fsa2luZy4gQ2FuJ3QgdHJ1c3QgYW55b25lLiBDb3VsZCBiZSBs\r\n"
        "eXJpdW0tYWRkbGVkLiBGYWRlLWNyYXplZC4gU3RpbGwsIGdvdCB0byBoYXZlIHNvbWUgY29udHJv\r\n"
        "bC4gV2hhdCBraW5kIG9mIGRhbWFnZSBzZW5kcyB0aGVzZSBkYWZ0IGZyZWFrcyBvdXQgaW4gdGhl\r\n"
        "IHN0cmVldHMgdGFsa2luZyB0byB0aGVtLi4uc2VsdmVzPyBBaGVtLg\r\n";

    const char* output = 
        "Well, that was a mess. Better get things in order before the Arishok responds. "
        "Can't be good. The viscount's son, Qunari in the Chantry. Bet it's going to rain, too. "
        "Hard enough doing this without soaking my hides. Thirty pounds of water and it's a march with no rations. "
        "When was the last time I ate? Who's cooking tonight? Sandal? Maker. Enchantment soup again. "
        "Thumb right in the bowl last time. His enchanting hand, too. Yeah, I saw you, you squirrely little knot-head. "
        "Did I lock my chambers? I'll bet he's in there now. Ugh. "
        "That guy looking at me? There's a lot of illness in this city. What's he looking at? Loony. "
        "Yeah, that's it, keep walking. Can't trust anyone. Could be lyrium-addled. Fade-crazed. "
        "Still, got to have some control. What kind of damage sends these daft freaks out in the streets talking to them...selves? "
        "Ahem.";

    TEST_ASSERT(verify_base_64_test(input, output));

}

void HeaderKeyImportTests::check_header_key_import() {
    const char* alice_fpr = "4ABE3AAF59AC32CFE4F86500A9411D176FF00E97";
    slurp_and_import_key(session, "test_keys/pub/pep-test-bob-0xC9C2EE39_pub.asc");
    slurp_and_import_key(session, "test_keys/priv/pep-test-bob-0xC9C2EE39_priv.asc");
    
    string message = slurp("test_mails/Header_key_import.eml");
    
    char* dec_msg = NULL;

    stringlist_t* keylist = NULL;

    PEP_rating rating;
    PEP_decrypt_flags_t flags;

    flags = 0;
    char* modified_src = NULL;
    PEP_STATUS status = MIME_decrypt_message(session, message.c_str(), message.size(), &dec_msg, &keylist, &rating, &flags, &modified_src);
    TEST_ASSERT_MSG(rating == PEP_rating_reliable, tl_rating_string(rating));
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));

    pEp_identity* alice_check = new_identity("pep.test.alice@pep-project.org", NULL, NULL, "pEp Test Alice");
    status = update_identity(session, alice_check);
    TEST_ASSERT_MSG(status == PEP_STATUS_OK, tl_status_string(status));
    TEST_ASSERT(alice_check->fpr);
    TEST_ASSERT_MSG(strcmp(alice_check->fpr, alice_fpr) == 0, alice_check->fpr);
    free(dec_msg);
    free(modified_src);
    free_identity(alice_check);
}
