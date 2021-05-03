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
from time import sleep


realhome = os.path.expanduser("~")
mydir = os.path.abspath(os.path.curdir)


def link_if_exists(dirname, arthome):
    "link directory from home to artificial home"

    orig = os.path.join(realhome, dirname)
    if os.path.exists(orig):
        if not os.path.exists(dirname):
            os.symlink(orig, dirname, True)


def create_own_identities(mydir, arthome, addr, username):
    "create own identities as part of the test setup"

    os.environ["HOME"] = os.path.join(mydir, arthome)
    os.environ["GNUPGHOME"] = os.path.join(mydir, arthome, 'gnupg')

    import pEp
    me = pEp.Identity()
    me.address = addr + "@peptest.ch"
    me.username = username

    pEp.myself(me)
    print(repr(me))


def link_file(filename):
    "sym-link file to version in parent directory"

    src = os.path.join(os.pardir, filename)
    if not os.path.exists(filename):
        os.symlink(src, filename, False)


def create_home(mydir, arthome, addr, username):
    "create an artificial home directory for testing"

    os.chdir(mydir)
    os.makedirs(arthome, exist_ok=True)

    os.chdir(arthome)

    link_if_exists("bin", arthome)
    link_if_exists("include", arthome)
    link_if_exists("lib", arthome)
    link_if_exists("share", arthome)
    link_if_exists(".local", arthome)
    link_if_exists("Library", arthome) # this may exist on macOS

    p = Process(target=create_own_identities,
                args=(mydir, arthome, addr, username))
    p.start()
    p.join()

    with open(".ready", "w"): pass


def create_homes():
    "create two artificial home directories for the two parties"

    try:
        os.stat("dummyhome1")
    except FileNotFoundError:
        create_home(mydir, "dummyhome1", "test1", "Alice One")
        create_home(mydir, "dummyhome2", "test2", "Bob Two")
        os.chdir(mydir);
        os.makedirs("common", exist_ok=True) # common inbox for Sync tests
    else:
        while True:
            try:
                os.stat("dummyhome1/.ready")
                os.stat("dummyhome2/.ready")
                break
            except:
                sleep(0.01)


def remove_homes():
    """remove formerly created artificial home directories including their
    contents"""

    os.chdir(mydir)
    shutil.rmtree("dummyhome1", ignore_errors=True)
    shutil.rmtree("dummyhome2", ignore_errors=True)
    shutil.rmtree("common", ignore_errors=True)
    shutil.rmtree("__pycache__", ignore_errors=True)


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

