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


realhome = os.path.expanduser("~")
mydir = os.path.abspath(os.path.curdir)


def link_if_exists(dirname, arthome):
    "link directory from home to artificial home"

    orig = os.path.join(realhome, dirname)
    if os.path.exists(orig):
        if not os.path.exists(dirname):
            os.symlink(orig, dirname, True)


def create_home(arthome):
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


def create_homes():
    "create two artificial home directories for the two parties"

    create_home("home1")
    create_home("home2")
    os.chdir(mydir)


def remove_homes():
    """remove formerly created artificial home directories including their
    contents"""

    os.chdir(mydir)
    shutil.rmtree("home1", ignore_errors=True)
    shutil.rmtree("home2", ignore_errors=True)


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

