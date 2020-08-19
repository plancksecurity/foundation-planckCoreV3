#!/usr/bin/env python3

# Note to python wizzes - I am not trying to be clever or efficient here. This
# is a convenience tool for ridiculous engine debugging fun, and I don't write
# python often. I am definitely not a member of the religion. YMMV, etc.
#
# If you break this, you buy it.
#

import sys

def parse_enum_line(line):
    line = line.strip()
    parts = line.split()
    if len(parts) != 3 or parts[1] != '=' or not parts[0].startswith("PEP_"):
        return
    key = int(parts[2].strip(','), 0)
    value = parts[0]
    valueDict[key] = value

def get_error(code):
    try:
        error = valueDict[code]
    except:
        print("Hah buddy! You wish!")
        exit(-1)

    print(str(code) + " -> " + error)    

error_val = int(sys.argv[1], 0)
if error_val == None:
    print("No error code, no error status!")
    exit(-1)


input_fname = "src/pEpEngine.h"

file = open(input_fname, 'r')
content = file.readlines()
file.close()

inStruct = False
valueDict = dict()

# This is super fragile. C'est la vie.
# If another struct is added first, expect chaos! ;)
#
for line in content:
    if line.startswith("} PEP_STATUS;"):
        break

    if not line.startswith("typedef enum {") and not inStruct:
        continue
    if not inStruct:
        inStruct = True
        continue

    parse_enum_line(line)

get_error(error_val)

