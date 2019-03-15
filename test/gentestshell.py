#! /usr/bin/env python3

import argparse
import os
import subprocess
import re

def decamel(name):
    retval = re.sub('([A-Z])', r'_\1', name).lower()
    return re.sub('^_', r'', retval) 

parser = argparse.ArgumentParser()
parser.add_argument("suite_name", help="(convention is <NameInUpperCamelCase>, e.g. StringpairList - suite created will then be StringpairListTests)")
parser.add_argument("--clobber", "-c", help="Overwrite extant files (must be explicitly indicated)", action='store_true')

gengroup = parser.add_mutually_exclusive_group()
gengroup.add_argument("--no_src", help="Generate header only, no source", action='store_true')
gengroup.add_argument("--no_hdr", help="Generate source only, no header", action='store_true')

typegroup = parser.add_mutually_exclusive_group()
typegroup.add_argument("--test", "-t", help="Just generate a generic test suite (no engine initialisation or db/gpg setup/teardown - default)", action='store_true')
typegroup.add_argument("--indiv", "-i", help="Generate a test suite with engine initialisation/release and gpg/db teardown between each test function", action='store_true')
typegroup.add_argument("--session", "-s", help="Generate a test suite with engine initialisation/release and gpg/db teardown only at the beginning and end of the test suite", action='store_true')

args = parser.parse_args()

suitename = args.suite_name
test_suite = suitename + "Tests"

superclass = "EngineTestSuite"

if args.indiv: 
    superclass = "EngineTestIndividualSuite"
elif args.session:
    superclass = "EngineTestSessionSuite"

print("\nCreating " + test_suite + " as an " + superclass + "\n")

uncamel = decamel(suitename)
print(uncamel)


nspace = "using namespace std;\n\n"

license = ("// This file is under GNU General Public License 3.0\n"
           "// see LICENSE.txt\n\n")

default_single_testname = "check_" + re.sub('_tests$', r'', uncamel) 

if not args.no_hdr:
    
    header_def = uncamel.upper() + "_H"

    deftxt = "#ifndef " + header_def + "\n#define " + header_def + "\n\n"

    header_inc = ("#include <string>\n" 
                  "#include \"" + superclass + ".h\"\n\n")

    header = license + deftxt + header_inc + nspace


    classdef = "class " + test_suite + " : public " + superclass + " {\n" + \
               "    public:\n" + \
               "        " + test_suite + "(string test_suite, string test_home_dir);\n" + \
               "    private:\n" \
               "        void " + default_single_testname + "();\n" + \
               "};\n" 

    header_file = header + classdef + "\n#endif\n"

    #print(header_file)

    do_write = True
    hfile_name = test_suite + ".h"
    hfile_path = os.path.join(os.path.join(os.getcwd(), "include"), hfile_name)

    if not args.clobber:
        if (os.path.isfile(hfile_path)):
            print(hfile_path + " exists. Not writing header file. Use --clobber to overwrite.")
            do_write = False

    if do_write:
        header_out = open(hfile_path, 'w')
        header_out.write(header_file)
        header_out.close()

if not args.no_src:
    src_inc = ('#include <stdlib.h>\n'
               '#include <string>\n\n'
               '#include "pEpEngine.h"\n\n'
               '#include "' + superclass +'.h"\n'
               '#include "' + test_suite + '.h"\n\n')

    test_suite_prefix = test_suite + "::"
    fname = test_suite_prefix + default_single_testname

    constructor = test_suite_prefix + test_suite + "(string suitename, string test_home_dir) :\n" + \
                  "    " + superclass + "::" + superclass + "(suitename, test_home_dir) {\n" + \
                  "    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string(\"" + fname + "\"),\n" + \
                  "                                                                      static_cast<Func>(&" + fname + ")));\n" + \
                  "}\n\n"
                  
    def_funct = "void " + test_suite_prefix + default_single_testname + "() {\n" + \
                "    TEST_ASSERT(true);\n" + \
                "}\n\n"

    src_file = license + src_inc + nspace + constructor + def_funct

    do_write = True
    sfile_name = test_suite + ".cc"
    sfile_path = os.path.join(os.path.join(os.getcwd(), "src/engine_tests"), sfile_name)

    if not args.clobber:
        if (os.path.isfile(sfile_path)):
            print(sfile_path + " exists. Not writing source file. Use --clobber to overwrite.")
            do_write = False

    if do_write:
        src_out = open(sfile_path, 'w')
        src_out.write(src_file)
        src_out.close()
