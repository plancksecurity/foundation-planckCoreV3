import os
import sys
import datetime
import re
import subprocess

SRC_PATH_STR = "./src"

function_list = []

import os

regi = re.compile('TEST_F\((.*), (.*)\)')

for root, dirs, files in os.walk(SRC_PATH_STR):
    for file in files:
        if file.endswith("Test.cc"):
            file_path = os.path.join(root, file)
            try:
                fd = open(file_path, 'r')
                for line in fd.readlines():
                    m = regi.match(line)
                    if (m != None):
                        function_list.append(m.group(1) + '.' + m.group(2))
            finally:
                fd.close()

# Ok, all of the functions are ready to go (we did this because
# we want to run each test *individually* through valgrind).
#
# let's run some tests!
# (Put in  --leak-check=full --show-leak-kinds=all for leak tests)
CMD_STR_PREFIX = "valgrind ./EngineTests --gtest_filter="

for test in function_list:
    CMD_STR = CMD_STR_PREFIX + test
    currentDT = datetime.datetime.now()

    outfile_prefix = "valgrind/" + test + "_" +currentDT.strftime("%Y%m%d%H%M%S")
    outfile = outfile_prefix + ".out"
    outfile_err = outfile_prefix + ".log"
    try:
        f_outfile = open(outfile, 'w')
        f_errfile = open(outfile_err, 'w')
        popen = subprocess.call(CMD_STR.split(), stdout=f_outfile, stderr=f_errfile)
    finally:
        f_outfile.close()
        f_errfile.close()
