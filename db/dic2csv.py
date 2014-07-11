#! /usr/bin/env python3

from argparse import ArgumentParser
from fileinput import FileInput, hook_encoded
import re, itertools, sys

try:
    from math import log2
except:
    from math import log
    def log2(x): return log(x) / log(2)

word = re.compile(r"(\S*?)(/|\s.*|$)")
unwanted = re.compile(r"(^\d|[^']*')")
space = re.compile(r'^\s')

p = ArgumentParser(description="create dictionary csv out of hunspell data")
p.add_argument('--hunspell', '-H', type=str, default="/usr/share/hunspell",
    help='directory where hunspell dictionary files reside (default: /usr/share/hunspell)')
p.add_argument('--lang', '-l', type=str, default="en_US",
    help='use dictionary for language LANG (default: en_US)')
p.add_argument('--encoding', '-e', type=str, default="utf-8",
    help='file encoding (default: utf-8)')

args = p.parse_args()

_all = (
    word.match(line).group(1).upper()
        for line in FileInput(
                args.hunspell + "/" + args.lang + ".dic",
                openhook=hook_encoded(args.encoding)
            )
        if not space.match(line)
)
_words = [w for w in _all if len(w) > 2 and not unwanted.match(w)]
_words.sort()
_words = [w for w, g in itertools.groupby(_words)]

if len(_words) > 65536:
    _words = _words[:65536]
elif len(_words) < 65536:
    sys.stderr.write(
            "warning for {}: only {:.2f} bit in wordlist, that makes {:.2f} bit for 5 words\n".format(
                    args.lang,
                    log2(len(_words)),
                    log2(len(_words))*5
                )
        )
    _words.extend(_words[:65536-len(_words)])

assert len(_words) == 65536, "lenght is {}".format(len(_words))

for i, w in enumerate(_words):
    print("{l},{i},{w},0".format(l=args.lang[:2], i=i, w=w))
