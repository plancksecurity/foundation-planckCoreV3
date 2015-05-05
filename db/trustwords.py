#!/usr/bin/env python3

from sqlite3 import connect
from os import environ
from argparse import ArgumentParser
from re import sub

try:
    environ["ALLUSERSPROFILE"]
except KeyError:
    db_file = "/usr/local/share/pEp/system.db"
else:
    db_file = environ["ALLUSERSPROFILE"] + r"\pEp\system.db"

p = ArgumentParser(description="show trustwords instead of hex fingerprint")
p.add_argument('--db-path', '-d', type=str, default=db_file,
        help='path to pEp system db (default: ' + db_file + ')')
p.add_argument('--lang', '-l', type=str, default="en",
        help='use dictionary for language LANG (default: en)')
p.add_argument('--short', '-s', action='store_true',
        help='display the first 5 of the trustwords')
p.add_argument('hex', metavar="hex", type=str, nargs='+',
        help='hex values of fingerprint')

args = p.parse_args()

c = connect(args.db_path).cursor()
hex_string = sub(r"\W", "", "".join(args.hex))

def hex_word(s):
    n = min(20, len(s)) if args.short else len(s)
    for i in range(0, n, 4):
        yield s[i:i+4]

r = []

for arg in hex_word(hex_string):
    c.execute("select word from wordlist where id = {} and lang = lower('{}')".format(
            str(int(arg, 16)), args.lang))
    r.append(c.fetchall()[0][0])

print(" ".join(r))
