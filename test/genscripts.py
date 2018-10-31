# This file is under GNU General Public License 3.0
# see LICENSE.txt

from os import listdir, getcwd
from os.path import isfile, join
from re import sub
import os
import stat
import datetime

srcpath = join(getcwd(), "src/engine_tests")

ls = listdir(srcpath)

for f in ls:
    if isfile(join(srcpath, f)):
        if (f.endswith(".cc")):
            suite = sub('\.cc$', '', f)
            outfile = open(suite, 'w')
            output = (
                "#!/bin/bash\n"
                "# This is a convenience script for launching individual tests and tab completion with TestDriver \n\n" +
                "./TestDriver " + suite + "\n\n")
            outfile.write(output)
            os.chmod(suite, 
                     (stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH | stat.S_IXGRP | stat.S_IXOTH))
            outfile.close()