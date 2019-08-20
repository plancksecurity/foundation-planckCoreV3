import re 
import sys

fixture_in = False 
removing_old_constructor = False
constructor_done = False
modline = None
filename = sys.argv[1]
outfile = sys.argv[2]

newfile = open(outfile,'w')

with open(filename) as fp: 
    for line in fp:
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
                    newfile.write(line)
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
                    newfile.write("#include <gtest/gtest.h>\n\n\n")
                    newfile.write("namespace {\n\n\t//The fixture for " + modline + "\n")
                    newfile.write("\tclass " + modline + " public ::testing::Test {\n")
                    newfile.write("\t\tpublic:\n")
                    newfile.write("\t\t\tEngine engine;\n")
                    newfile.write("\t\t\tPEP_SESSION session;\n\n")
                    newfile.write("\t\tprotected:\n")
                    newfile.write("\t\t\t// You can remove any or all of the following functions if its body\n")
                    newfile.write("\t\t\t// is empty.\n")
                    newfile.write("\t\t\t" + modline + "() {\n")
                    newfile.write("\t\t\t\t// You can do set-up work for each test here.\n")
                    newfile.write("\t\t\t\ttest_suite_name = ::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name();\n")
                    newfile.write("\t\t\t\ttest_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();\n")
                    newfile.write("\t\t\t\t")
                    newfile.write("\t\t\t\t")
                    newfile.write("\t\t\t\t")
                    newfile.write("\t\t\t\t")                    
                    newfile.write("\t\t\t}\n\n")
                    newfile.write("\t\t\t~" + modline + "() override {\n")
                    newfile.write("\t\t\t\t// You can do clean-up work that doesn't throw exceptions here.\n")
                    newfile.write("\t\t\t}\n\n")
                    newfile.write("\t\t\t// If the constructor and destructor are not enough for setting up\n")
                    newfile.write("\t\t\t// and cleaning up each test, you can define the following methods:\n\n")
                    newfile.write("\t\t\tvoid SetUp() override {\n")
                    newfile.write("\t\t\t\t// Code here will be called immediately after the constructor (right\n")
                    newfile.write("\t\t\t\t// before each test).\n")
                    newfile.write("\t\t\t}\n\n")
                    newfile.write("\t\t\tvoid TearDown() override {\n")
                    newfile.write("\t\t\t\t// Code here will be called immediately after each test (right\n")
                    newfile.write("\t\t\t}\n\n")
                    newfile.write("\t\tprivate:\n");
                    newfile.write("\t\t\tconst char* test_suite_name;\n")
                    newfile.write("\t\t\tconst char* test_name;\n")                                        
                    newfile.write("\t\t\t// Objects declared here can be used by all tests in the " + modline + " suite.\n\n")
                    newfile.write("\t};\n\n")
                    newfile.write("}  // namespace\n\n\n")

                    fixture_in = True
        else:
            #void *Tests::check*() {
            # -> TEST_F(*Test, check*) {
            modline = re.sub(r'void\s*(.*)Tests::check(.*)\(\);', r'TEST_F(\1Test, check\2);', line)
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
            # -> ASSERT_EQ(<x>, nullptr);
            modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*==\s*NULL,.*\);',r'ASSERT_EQ(\1, nullptr);', line)
            if (line != modline):
                newfile.write(modline + "\n")
                continue
            modline = re.sub(r'TEST_ASSERT\((.*)\s*==\s*NULL\);', r'ASSERT_EQ(\1, nullptr);',line)
            if (line != modline):
                newfile.write(modline + "\n")
                continue
            
            #TEST_ASSERT_MSG(<x> != NULL, *);
            #TEST_ASSERT(<x> != NULL);
            # -> ASSERT_NE(<x>, nullptr);
            modline = re.sub(r'TEST_ASSERT_MSG\((.*)\s*!=\s*NULL,.*\);',r'ASSERT_NE(\1, nullptr);', line)
            if (line != modline):
                newfile.write(modline + "\n")
                continue
            modline = re.sub(r'TEST_ASSERT\((.*)\s*!=\s*NULL\);', r'ASSERT_NE(\1, nullptr);',line)
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
            
            # FIXME: either assume ptr or ask about it?
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
                    modline = re.sub(r'TEST_ASSERT_MSG\(!(.*),.*\);',r'ASSERT_NE(\1, nullptr);', line)
                    if (line != modline):
                        newfile.write(modline + "\n")
                        continue
                    modline = re.sub(r'TEST_ASSERT\(!(.*)\);', r'ASSERT_NE(\1, nullptr);',line)
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
                    modline = re.sub(r'TEST_ASSERT_MSG\((.*),.*\);',r'ASSERT_NE(\1, nullptr);', line)
                    if (line != modline):
                        newfile.write(modline + "\n")
                        continue
                    modline = re.sub(r'TEST_ASSERT\((.*)\);', r'ASSERT_NE(\1, nullptr);',line)
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
