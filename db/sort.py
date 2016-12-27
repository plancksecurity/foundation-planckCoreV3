#! /usr/bin/env python3

# This file is under GNU General Public License 3.0
# see LICENSE.txt


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
p.add_argument('--full', '-f', action='store_true',
    help="full list - don't reduce to 65536 words")

args = p.parse_args()

try:
    from icu import UnicodeString, Locale
except ImportError:
    print("warning: PyICU not installed, using fallback", file=sys.stderr)
    def upper(x):
        return x.upper();
else:
    locale = Locale(args.lang)
    def upper(x):
        u = UnicodeString(x)
        return str(u.toUpper(locale))

_all = (
    upper(word.match(line).group(1))
        for line in FileInput(
                args.hunspell + "/" + args.lang + ".dic",
                openhook=hook_encoded(args.encoding)
            )
        if not space.match(line)
)
_words = [w for w in _all if len(w) > 2 and not unwanted.match(w)]
_words.sort()
_words = [w for w, g in itertools.groupby(_words)]

if not args.full:
    while len(_words) > 65536 * 2:
        _words = _words[::2]

if len(_words) > 65536:
    if not args.full:
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

if not args.full:
    assert len(_words) == 65536, "lenght is {}".format(len(_words))

for i, w in enumerate(_words):
    print("{l},{i},{w},0".format(l=args.lang[:2], i=i, w=w))
