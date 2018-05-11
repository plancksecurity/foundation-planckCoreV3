# This file is under GNU General Public License 3.0
# see LICENSE.txt

from os import listdir, getcwd
from os.path import isfile, join
import re
import string
import subprocess

srcpath = getcwd()

ls = listdir(srcpath)

files = []

for f in ls:
    if isfile(join(srcpath, f)):
        if (f.endswith("_test.cc")):
            testname = re.sub('_test.cc$', r'', f)
            testname = (string.capwords(testname,'_')).replace("_", "")
            CMD_STR = "python3 ./gentestshell.py -c -s " + testname
            print(CMD_STR)
            subprocess.run(CMD_STR.split(' '))
