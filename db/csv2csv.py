#! /usr/bin/env python3

from argparse import ArgumentParser
from fileinput import FileInput, hook_encoded
import re, itertools, sys

space = re.compile(r'^\s')

p = ArgumentParser(description="re-write re-order csv and strip lines with too long words")
p.add_argument('--input', '-i', type=str, default="somefile.cvs",
    help='input file')
p.add_argument('--length', '-l', type=int, default=100,
    help='min word length to stripp a line')

args = p.parse_args()

try:
    from icu import UnicodeString, Locale
except ImportError:
    print("warning: PyICU not installed, using fallback", file=sys.stderr)
else:
    locale = Locale("utf-8")

_all = (
        line.split(',')
        for line in FileInput(
                args.input,
                openhook=hook_encoded("utf-8")
            )
        if not space.match(line)
)

_some = (line for line in _all if len(line[2]) < args.length)

for i, w in enumerate(_some):
    print("{l},{i},{w},0".format(l=w[0], i=i, w=w[2]))
