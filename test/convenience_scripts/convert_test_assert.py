import sys
import argparse
import re

def get_closing_parenthesis(paren_start):
    paren_level = 0
    index = 0
    
    for c in paren_start:
        if c == '(':
            paren_level += 1
        elif c == ')':
            paren_level -= 1
        
        if paren_level == 0:
            break;
        
        index += 1
        
    return index

# TEST_ASSERT(assertion blah blah)
# want: TEST_ASSERT_MSG(assertion blah blah, "AUTOMSG: assertion blah blah")

parser = argparse.ArgumentParser()
parser.add_argument('files', nargs = '*', help = 'files to convert')
args = parser.parse_args()

# if not args.files:
#     print("ERROR: Can't make something from nothing. See: first law of thermodynamics.")
#     sys.exit(1)

for f in args.files:
    infile = open(f, "r");
    lines = infile.readlines();

    output = ""
    
    # For each line in file - too lazy for regex this morning
    for l in lines:
        output_line = l
        old_assert = "TEST_ASSERT("
        old_assert_len = len(old_assert)
        
        l_index = l.find(old_assert)
        
        # if this line contains "TEST_ASSERT("
        if (l_index >= 0):
            # 1. get replaceable string (TEST_ASSERT(assertion blah blah)) 
            old_r_index = l.find(")", l_index)
            paren_start = l_index + old_assert_len - 1
            r_index = paren_start + get_closing_parenthesis(l[paren_start:])
                
            #print("l is " + str(l_index) + " and r is " + str(not_r_index))
            
            # 2. filter to get assertion
            assertion = l[l_index + old_assert_len:r_index]
#            print("Assertion is " + assertion)
            # 3. create replacement
            new_assert = "TEST_ASSERT_MSG((" + assertion + "), \"" + assertion.replace('"','\\"') + "\")"
#            print("New assertion is " + new_assert)
            # 4. replace
            output_line = l[0:l_index] + new_assert + l[r_index + 1:]
            
        output += (output_line)
        l_index = 0

    print(output)
    
    infile.close()
    
    outfile = open(f, "w")
    outfile.write(output)
    outfile.close()
