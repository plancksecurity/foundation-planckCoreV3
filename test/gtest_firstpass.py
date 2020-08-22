import re 
import sys
import os

def tb(n):
    retval = ""
    for i in range(n):
        retval = retval + "    "
    return retval
        
#filename = sys.argv[1]
#outfile = sys.argv[2]

for filename in os.listdir("src"):
    fixture_in = False 
    removing_old_constructor = False
    constructor_done = False
    modline = None
    eat_next_line = False;
    
    if not filename.endswith("Tests.cc"):
        continue
        
    outfile = filename[:-4] + ".cc"
    
    print("Output file is " + outfile)
        
    newfile = open(os.path.join("src", outfile),'w')

    with open(os.path.join("src", filename)) as fp: 
        for line in fp:
            if (eat_next_line):
                eat_next_line = False;
                continue;
            line = line.rstrip();
            
            if not fixture_in:
                if (removing_old_constructor):
                    if "}" in line:
                        removing_old_constructor = False  
                        constructor_done = True 
                    continue
                else:        
                    if (line.find("namespace") >= 0):
                        continue
                    if (line.find("Tests.h") >= 0):
                        continue
                    if (line.find("cpptest") >= 0):
                        continue 
                    if (line.find("EngineTestSuite.h") >= 0 or line.find("EngineTestIndividualSuite.h") >= 0 or line.find("EngineTestSessionSuite.h") >= 0):
                        continue
                    
                    if (modline == None):                
                        modline = re.sub(r'(.*)Tests::(.*)Tests\(string suitename, string test_home_dir\) :', r'\1Test', line)                
                        
                    if(modline == line):
                        newfile.write(line + "\n")
                        modline = None
                        continue
                    else:
                        if not (constructor_done):
                            removing_old_constructor = True
                            continue    
                            
                        #*Tests::*Tests(string suitename, string test_home_dir)
                        # Put in fixture blob
                        # - delete through first }
                        #print(modline) 
                        newfile.write("#include \"Engine.h\"\n\n")                    
                        newfile.write("#include <gtest/gtest.h>\n\n\n")
                        newfile.write("namespace {\n\n\t//The fixture for " + modline + "\n")
                        newfile.write(tb(1) + "class " + modline + " : public ::testing::Test {\n")
                        newfile.write(tb(2) + "public:\n")
                        newfile.write(tb(3) + "Engine* engine;\n")
                        newfile.write(tb(3) + "PEP_SESSION session;\n\n")
                        newfile.write(tb(2) + "protected:\n")
                        newfile.write(tb(3) + "// You can remove any or all of the following functions if its body\n")
                        newfile.write(tb(3) + "// is empty.\n")
                        newfile.write(tb(3) + "" + modline + "() {\n")
                        newfile.write(tb(4) + "// You can do set-up work for each test here.\n")
                        newfile.write(tb(4) + "test_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->GTEST_SUITE_SYM();\n")
                        newfile.write(tb(4) + "test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();\n")
                        newfile.write(tb(4) + "test_path = get_main_test_home_dir() + \"/\" + test_suite_name + \"/\" + test_name;\n")
                        newfile.write(tb(3) + "}\n\n")
                        newfile.write(tb(3) + "~" + modline + "() override {\n")
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
                        newfile.write(tb(4) + "engine->prep(NULL, NULL, init_files);\n")
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
                        newfile.write(tb(3) + "// Objects declared here can be used by all tests in the " + modline + " suite.\n\n")
                        newfile.write(tb(1) + "};\n\n")
                        newfile.write("}  // namespace\n\n\n")

                        fixture_in = True
            else:
                #void *Tests::check*() {
                # -> TEST_F(*Test, check*) {
                modline = re.sub(r'void\s*(.*)Tests::check(.*)\(\)\s*{', r'TEST_F(\1Test, check\2) {', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                    
                #TEST_ASSERT(true)
                # -> <nothing>                
                if (line.find("TEST_ASSERT(true)") >= 0):
                    continue
                    
                #TEST_ASSERT_MSG(strcmp(blah,blah) == 0, *)
                #TEST_ASSERT(strcmp(blah,blah == 0))
                # -> ASSERT_STREQ(blah,blah)
                modline = re.sub(r'TEST_ASSERT_MSG\(\s*strcmp\(\s*(.*),\s*(.*)\)\s*==\s*0\s*,.*\);', r'ASSERT_STREQ(\1, \2);', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\(\s*strcmp\(\s*(.*),\s*(.*)\)\s*==\s*0\);', r'ASSERT_STREQ(\1, \2);', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue

                #TEST_ASSERT_MSG(strcmp(blah,blah) != 0, *)
                #TEST_ASSERT(strcmp(blah,blah != 0))
                # -> ASSERT_STREQ(blah,blah)
                modline = re.sub(r'TEST_ASSERT_MSG\(\s*strcmp\(\s*(.*),\s*(.*)\)\s*!=\s*0\s*,.*\);', r'ASSERT_STRNE(\1, \2);', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\(\s*strcmp\(\s*(.*),\s*(.*)\)\s*!=\s*0\);', r'ASSERT_STRNE(\1, \2);', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                    
                #TEST_ASSERT_MSG(<x> == NULL, *);
                #TEST_ASSERT(<x> == NULL);
                # -> ASSERT_NULL(<x>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*==\s*NULL,.*\);',r'ASSERT_NULL(\1);', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*==\s*NULL\);', r'ASSERT_NULL(\1);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> != NULL, *);
                #TEST_ASSERT(<x> != NULL);
                # -> ASSERT_NOTNULL(<x>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*!=\s*NULL,.*\);',r'ASSERT_NOTNULL(\1);', line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*!=\s*NULL\);', r'ASSERT_NOTNULL(\1);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> == <y>, *);
                #TEST_ASSERT(<x> == <y>);
                # -> ASSERT_EQ(<x>, <y>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*==\s*(.*),.*\);', r'ASSERT_EQ(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*==\s*(.*)\);', r'ASSERT_EQ(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> != <y>, *);
                #TEST_ASSERT(<x> != <y>);
                # -> ASSERT_NE(<x>, <y>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*!=\s*(.*),.*\);', r'ASSERT_NE(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*!=\s*(.*)\);', r'ASSERT_NE(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> >= <y>, *);
                #TEST_ASSERT(<x> >= <y>);
                # -> ASSERT_GE(<x>, <y>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*[^-]>=\s*(.*),.*\);', r'ASSERT_GE(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*[^-]>=\s*(.*)\);', r'ASSERT_GE(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> > <y>, *);
                #TEST_ASSERT(<x> > <y>);
                # -> ASSERT_GT(<x>, <y>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*[^-]>\s*(.*),.*\);', r'ASSERT_GT(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*[^-]>\s*(.*)\);', r'ASSERT_GT(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> <= <y>, *);
                #TEST_ASSERT(<x> <= <y>);
                # -> ASSERT_LE(<x>, <y>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*<=\s*(.*),.*\);', r'ASSERT_LE(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*<=\s*(.*)\);', r'ASSERT_LE(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(<x> < <y>, *);
                #TEST_ASSERT(<x> < <y>);
                # -> ASSERT_LT(<x>, <y>);
                modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*<\s*(.*),.*\);', r'ASSERT_LT(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\((.*)\s*<\s*(.*)\);', r'ASSERT_LT(\1, \2);',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue

                #TEST_ASSERT_MSG(slurp_and_import_key(
                #TEST_ASSERT(slurp_and_import_key(
                # -> ASSERT_TRUE(slurp_and_import_key(
                modline = re.sub(r'TEST_ASSERT_MSG\(slurp_and_import_key', r'ASSERT_TRUE(slurp_and_import_key',line)
                if (line != modline):
                    if not line.endswith(";"):
                        eat_next_line = True
                        modline = re.sub(r'\),', r'));', modline);
                    newfile.write(modline + "\n")
                    continue
                modline = re.sub(r'TEST_ASSERT\(slurp_and_import_key', r'ASSERT_TRUE(slurp_and_import_key',line)
                if (line != modline):
                    newfile.write(modline + "\n")
                    continue
                
                #TEST_ASSERT_MSG(!<x>, *);
                #TEST_ASSERT(!<x>);
                # -> ASSERT_FALSE(<x>);
                mgroup = re.match(r'TEST_ASSERT_MSG\(!(.*),.*\);', line.lstrip());
                if (mgroup == None):
                    mgroup = re.match(r'TEST_ASSERT\(!(.*)\);', line.lstrip());
                
                if (mgroup != None):
                    matchphrase = mgroup.group(0)
                    is_pointer = False
                    while True:
                        answer = input("ATTENTION: INPUT REQUIRED: In line " + line.lstrip() + ", is " + matchphrase + " a pointer? (y/n)")
                        if (answer == "y" or answer == "Y"):
                            is_pointer = True
                            break
                        elif (answer != "n" and answer != 'N'):
                            print("\'" + answer + "\' is not a valid answer. Please answer with 'y' or 'n'.") 
                            continue
                        break;       
                    
                    if (is_pointer):
                        modline = re.sub(r'TEST_ASSERT_MSG\(!(.*),.*\);',r'ASSERT_NOTNULL(\1);', line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                        modline = re.sub(r'TEST_ASSERT\(!(.*)\);', r'ASSERT_NOTNULL(\1);',line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                    else:        
                        modline = re.sub(r'TEST_ASSERT_MSG\(!(.*),.*\);',r'ASSERT_FALSE(\1);', line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                        modline = re.sub(r'TEST_ASSERT\(!(.*)\);', r'ASSERT_FALSE(\1);',line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                                                
                #TEST_ASSERT_MSG(<x>, *);
                #TEST_ASSERT(<x>);
                # -> ASSERT_TRUE(<x>);
                mgroup = re.match(r'TEST_ASSERT_MSG\((.*),.*\);', line.lstrip());
                if (mgroup == None):
                    mgroup = re.match(r'TEST_ASSERT\((.*)\);', line.lstrip());
                
                if (mgroup != None):
                    matchphrase = mgroup.group(1)
                    is_pointer = False
                    while True:
                        answer = input("ATTENTION: INPUT REQUIRED: In line " + line.lstrip() + ", is " + matchphrase + " a pointer? (y/n)")
                        if (answer == "y" or answer == "Y"):
                            is_pointer = True
                            break
                        elif (answer != "n" and answer != 'N'):
                            print("\'" + answer + "\' is not a valid answer. Please answer with 'y' or 'n'.") 
                            continue
                        break;       
                    
                    if (is_pointer):
                        modline = re.sub(r'TEST_ASSERT_MSG\((.*),.*\);',r'ASSERT_NOTNULL(\1);', line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                        modline = re.sub(r'TEST_ASSERT\((.*)\);', r'ASSERT_NOTNULL(\1);',line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                    else:        
                        modline = re.sub(r'TEST_ASSERT_MSG\((.*),.*\);',r'ASSERT_TRUE(\1);', line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                        modline = re.sub(r'TEST_ASSERT\((.*)\);', r'ASSERT_TRUE(\1);',line)
                        if (line != modline):
                            newfile.write(modline + "\n")
                            continue
                
                #Ok, it's something else. Print line and go.
                newfile.write(line + "\n")
