import argparse
import os
import subprocess
import re

def decamel(name):
    retval = re.sub('([A-Z])', r'_\1', name).lower()
    return re.sub('^_', r'', retval) 

def tb(n):
    retval = ""
    for i in range(n):
        retval = retval + "    "
    return retval

parser = argparse.ArgumentParser()
parser.add_argument("suite_name", help="(convention is <NameInUpperCamelCase>, e.g. StringpairList - suite created will then be StringpairListTests)")
parser.add_argument("--clobber", "-c", help="Overwrite extant files (must be explicitly indicated)", action='store_true')

args = parser.parse_args()

suitename = args.suite_name
test_suite = suitename + "Test"

nspace = "using namespace std;\n\n"

newfile = open(os.path.join("src", test_suite + ".cc"), 'w')

license = ("// This file is under GNU General Public License 3.0\n"
           "// see LICENSE.txt\n\n")

newfile.write("#include <stdlib.h>\n")
newfile.write("#include <string>\n")
newfile.write("#include <cstring>\n\n")
newfile.write("#include \"pEpEngine.h\"\n")
newfile.write("#include \"TestUtilities.h\"\n")
newfile.write("#include \"TestConstants.h\"\n")
newfile.write("#include \"Engine.h\"\n\n")                    
newfile.write("#include <gtest/gtest.h>\n\n\n")
newfile.write("namespace {\n\n\t//The fixture for " + test_suite + "\n")
newfile.write(tb(1) + "class " + test_suite + " : public ::testing::Test {\n")
newfile.write(tb(2) + "public:\n")
newfile.write(tb(3) + "Engine* engine;\n")
newfile.write(tb(3) + "PEP_SESSION session;\n\n")
newfile.write(tb(2) + "protected:\n")
newfile.write(tb(3) + "// You can remove any or all of the following functions if its body\n")
newfile.write(tb(3) + "// is empty.\n")
newfile.write(tb(3) + test_suite + "() {\n")
newfile.write(tb(4) + "// You can do set-up work for each test here.\n")
newfile.write(tb(4) + "test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();\n")
newfile.write(tb(4) + "test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();\n")
newfile.write(tb(4) + "test_path = get_main_test_home_dir() + \"/\" + test_suite_name + \"/\" + test_name;\n")
newfile.write(tb(3) + "}\n\n")
newfile.write(tb(3) + "~" + test_suite + "() override {\n")
newfile.write(tb(4) + "// You can do clean-up work that doesn't throw exceptions here.\n")
newfile.write(tb(3) + "}\n\n")
newfile.write(tb(3) + "// If the constructor and destructor are not enough for setting up\n")
newfile.write(tb(3) + "// and cleaning up each test, you can define the following methods:\n\n")
newfile.write(tb(3) + "void SetUp() override {\n")
newfile.write(tb(4) + "// Code here will be called immediately after the constructor (right\n")
newfile.write(tb(4) + "// before each test).\n")
newfile.write("\n" + tb(4) + "// Leave this empty if there are no files to copy to the home directory path\n")
newfile.write(tb(4) + "std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();\n")                                        
newfile.write("\n" + tb(4) + "// Get a new test Engine.\n")                    
newfile.write(tb(4) + "engine = new Engine(test_path);\n");
newfile.write(tb(4) + "ASSERT_NOTNULL(engine);\n")
newfile.write("\n" + tb(4) + "// Ok, let's initialize test directories etc.\n")                                        
newfile.write(tb(4) + "engine->prep(NULL, NULL, NULL, init_files);\n")
newfile.write("\n" + tb(4) + "// Ok, try to start this bugger.\n")                    
newfile.write(tb(4) + "engine->start();\n")                    
newfile.write(tb(4) + "ASSERT_NOTNULL(engine->session);\n")                    
newfile.write(tb(4) + "session = engine->session;\n") 
newfile.write("\n" + tb(4) + "// Engine is up. Keep on truckin\'\n");                                                            
newfile.write(tb(3) + "}\n\n")
newfile.write(tb(3) + "void TearDown() override {\n")
newfile.write(tb(4) + "// Code here will be called immediately after each test (right\n")
newfile.write(tb(4) + "// before the destructor).\n")   
newfile.write(tb(4) + "engine->shut_down();\n")
newfile.write(tb(4) + "delete engine;\n")                    
newfile.write(tb(4) + "engine = NULL;\n")                    
newfile.write(tb(4) + "session = NULL;\n")                    
newfile.write(tb(3) + "}\n\n")
newfile.write(tb(2) + "private:\n");
newfile.write(tb(3) + "const char* test_suite_name;\n")
newfile.write(tb(3) + "const char* test_name;\n")                                                            
newfile.write(tb(3) + "string test_path;\n") 
newfile.write(tb(3) + "// Objects declared here can be used by all tests in the " + test_suite + " suite.\n\n")
newfile.write(tb(1) + "};\n\n")
newfile.write("}  // namespace\n\n\n")
newfile.write("TEST_F(" + test_suite + ", check_" + decamel(suitename) + ") {\n")
newfile.write(tb(1) + "// This is just a dummy test case. The convention is check_whatever_you_are_checking\n")
newfile.write(tb(1) + "// so for multiple test cases in a suite, be more explicit ;)\n")
newfile.write("}\n")
