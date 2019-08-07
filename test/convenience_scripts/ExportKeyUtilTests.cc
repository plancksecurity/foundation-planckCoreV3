// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include <stdlib.h>
#include <cstring>
#include <string>
#include <fstream>
#include <iostream>

#include <cpptest.h>
#include "test_util.h"

#include "pEpEngine.h"

#include "EngineTestIndividualSuite.h"
#include "ExportKeyUtilTests.h"

using namespace std;

ExportKeyUtilTests::ExportKeyUtilTests(string suitename, string test_home_dir) :
    EngineTestIndividualSuite::EngineTestIndividualSuite(suitename, test_home_dir) {
    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string("ExportKeyUtilTests::check_export_key_util"),
                                                                      static_cast<Func>(&ExportKeyUtilTests::check_export_key_util)));
}

void ExportKeyUtilTests::setup() {
    string key_db_name;
    cout << "Please indicate the name of the key DB file: ";
    cin >> key_db_name;
    add_file_to_home_dir_queue(key_db_name, ".pEp_keys.db");
    EngineTestIndividualSuite::setup();
}

void ExportKeyUtilTests::check_export_key_util() {
    string search_term;
    string output_file;
    cout << "Please give address (containing @) or key_id to dump: ";
    cin >> search_term;
    stringlist_t* keylist = NULL;
    PEP_STATUS status = find_keys(session, search_term.c_str(), &keylist);
    TEST_ASSERT(status == PEP_STATUS_OK);
    TEST_ASSERT(keylist);
    string priv;
    cout << "Private keys? (y/N)";
    cin >> priv;
    string outdir;
    cout << "Output directory? (curdir is default)";
    cin >> outdir;
    stringlist_t* curr = keylist;
    while (curr) {
        string fpr = curr->value;
        if (!fpr.empty()) {
            char* key = NULL;
            size_t size = 0;
            status = export_key(session, fpr.c_str(), &key, &size);
            if (key && size != 0) {
                ofstream outfile;
                outfile.open(((outdir.empty() ? fpr : outdir + "/" + fpr) + "_pub.asc").c_str());
                outfile.write(key, size);
                outfile.close();
            }
            free(key);
            size = 0;
            key = NULL;
            if (priv.c_str()[0] == 'y' || priv.c_str()[0] == 'Y') {
                status = export_secret_key(session, fpr.c_str(), &key, &size);
                if (key && size != 0) {
                    ofstream outfile;
                    outfile.open(((outdir.empty() ? fpr : outdir + "/" + fpr) + "_pub.asc").c_str());
                    outfile.write(key, size);
                    outfile.close();                    
                }                
            }   
            free(key);
        }
        curr = curr->next;
    }
    
    TEST_ASSERT(true);
}
