#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# this file is under GNU General Public License 3.0
# Copyleft 2017, p≡p foundation

#import vimpdb; vimpdb.set_trace()


"""
This script is setting up the test environment by creating two home directories
for simulation of message exchange between two p≡p parties.

The directories are created in the current directory.
"""


import os
import shutil
from multiprocessing import Process


realhome = os.path.expanduser("~")
mydir = os.path.abspath(os.path.curdir)
files_to_copy = ("transport.py",)


def link_if_exists(dirname, arthome):
    "link directory from home to artificial home"

    orig = os.path.join(realhome, dirname)
    if os.path.exists(orig):
        if not os.path.exists(dirname):
            os.symlink(orig, dirname, True)


def create_home(mydir, arthome):
    "create an artificial home directory for testing"

    os.chdir(mydir)
    os.makedirs(arthome, exist_ok=True)

    os.chdir(arthome)
    for filename in files_to_copy:
        src = os.path.join(os.pardir, filename)
        shutil.copyfile(src, filename)

    link_if_exists("bin", arthome)
    link_if_exists("include", arthome)
    link_if_exists("lib", arthome)
    link_if_exists("share", arthome)
    link_if_exists(".local", arthome)
    link_if_exists("Library", arthome) # this may exist on macOS


def create_own_identities(mydir, arthome, username):
    "create own identities as part of the test setup"

    os.environ["HOME"] = os.path.join(mydir, arthome)
    os.environ["GNUPGHOME"] = os.path.join(mydir, arthome, '.gnupg')

    import pEp
    me = pEp.Identity()
    me.address = arthome + "@peptest.ch"
    me.username = username

    pEp.myself(me)
    print(repr(me))


def create_homes():
    "create two artificial home directories for the two parties"

    create_home(mydir, "test1")

    p1 = Process(target=create_own_identities, args=(mydir, 'test1',
            'Alice One'))
    p1.start()
    p1.join()

    create_home(mydir, "test2")

    p2 = Process(target=create_own_identities, args=(mydir, 'test2',
            'Bob Two'))
    p2.start()
    p2.join()


def remove_homes():
    """remove formerly created artificial home directories including their
    contents"""

    os.chdir(mydir)
    shutil.rmtree("test1", ignore_errors=True)
    shutil.rmtree("test2", ignore_errors=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-r', '--remove', action="store_true",
            help=remove_homes.__doc__)

    args = parser.parse_args()

    if args.remove:
        remove_homes()
    else:
        create_homes()

