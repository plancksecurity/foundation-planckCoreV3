#!/usr/bin/env python3

# Note to python wizzes - I am not trying to be clever or efficient here. This
# is a convenience tool for ridiculous engine debugging fun, and I don't write
# python often. I am definitely not a member of the religion. YMMV, etc.
#
# If you break this, you buy it.
#

import sys
import argparse

def parse_enum_line(line, ct):
    line = line.strip()
    if (line.startswith("//") or line == ""):
        return

    parts = []

    if (ct):
        temp = line.split(",")
        if len(temp) == 0:
            return
        else:
            parts = temp[0].split()

    else:    
        parts = line.split()

    if len(parts) != 3 or parts[1] != '=':
        return
    if not ct and not parts[0].startswith("PEP_"):
        return
    elif ct and not parts[0].startswith("PEP_ct_"):
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

parser = argparse.ArgumentParser()
parser.add_argument("value", type=int)
parser.add_argument("--comm_type", "-ct", help="number represents a comm type", action='store_true')

args = parser.parse_args()

error_val = args.value

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
    if not args.comm_type: 
        if line.startswith("} PEP_STATUS;"):
            break
    else:
        if line.startswith("} PEP_comm_type;"):
            break    

    if ((not args.comm_type and not line.startswith("typedef enum {")) or (args.comm_type and not line.startswith("typedef enum _PEP_comm_type {"))) and not inStruct:
        continue
    if not inStruct:
        inStruct = True
        continue

    parse_enum_line(line, args.comm_type)

get_error(error_val)

