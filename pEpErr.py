#!/usr/bin/env python3

# Note to python wizzes - I am not trying to be clever or efficient here. This
# is a convenience tool for ridiculous engine debugging fun, and I don't write
# python often. I am definitely not a member of the religion. YMMV, etc.
#
# If you break this, you buy it.
#

import sys
import argparse

def parse_enum_line(line, ct, r):
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

    if len(parts) < 3 or parts[1] != '=':
        return
    if r and not parts[0].startswith("PEP_rating"):
        return
    elif ct and not parts[0].startswith("PEP_ct_"):
        return
    elif not ct and not r and not parts[0].startswith("PEP_"):
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
parser.add_argument("--rating", "-r", help="number represents a rating", action='store_true')

args = parser.parse_args()

error_val = args.value

input_fname = ""

if not args.rating:
    input_fname = "src/pEpEngine.h"
else:
    input_fname = "src/message_api.h"
print(input_fname)
pEp_error = not (args.rating or args.comm_type)

file = open(input_fname, 'r')
content = file.readlines()
file.close()

inStruct = False
valueDict = dict()

# This is super fragile. C'est la vie.
# If another struct is added first, expect chaos! ;)
#
for line in content:
    if args.rating:
        if line.startswith("} PEP_rating;"):
            break
    elif args.comm_type: 
        if line.startswith("} PEP_comm_type;"):
            break
    elif line.startswith("} PEP_STATUS;"):
            break    
        
    if not inStruct:
        if (args.rating and not line.startswith("typedef enum _PEP_rating {")) or \
            (args.comm_type and not line.startswith("typedef enum _PEP_comm_type {")) or \
            (pEp_error and not line.startswith("typedef enum {")):
            continue
        else:
            inStruct = True
            continue

    parse_enum_line(line, args.comm_type, args.rating)

get_error(error_val)

