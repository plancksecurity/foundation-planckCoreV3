#!/usr/bin/env python3

#
# Updates the list of engine-generated files.
#
# Usage (from the top of the checked out engine):
# python3 build-mac/scripts/python/update_engine_generated_files.py
#

import os
import subprocess

from os.path import isfile, join, splitext

# The engine source directory
ENGINE_BASE_DIR = '.'

SYNC_DIR_GENERATED = join(ENGINE_BASE_DIR, 'codegen/generated')
ASN_DIR_GENERATED = join(ENGINE_BASE_DIR, 'asn.1')
DES_DIR = join(ENGINE_BASE_DIR, 'build-mac')
DES_DIR_ASN = join(ENGINE_BASE_DIR, 'build-mac', 'Subprojects', 'pEpASN1')
DEST_ASN_LIST = join(DES_DIR_ASN, 'generated-files.txt')
DEST_SYNC_LIST = join(DES_DIR, 'generated-files.txt')


class Pushd:
    """Context manager for changing the current working directory"""

    def __init__(self, new_path):
        self.new_path = os.path.expanduser(new_path)

    def __enter__(self):
        self.saved_path = os.getcwd()
        os.chdir(self.new_path)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.saved_path)


def cfiles(path):
    """Returns an array of .c and .h files under the given directory"""
    return [f for f in os.listdir(path)
            if isfile(join(path, f))
            and splitext(f)[1] in ['.c', '.h']]


def clean_engine():
    """Cleans the engine"""
    with Pushd(ENGINE_BASE_DIR):
        subprocess.run(['gmake', 'clean'], check=True)


def generate_files():
    """Generates the engine's sync files"""
    with Pushd(ENGINE_BASE_DIR):
        commands = [
            ['gmake', 'codegen'],
            ['gmake', '-C', 'asn.1', 'Sync.c', 'Distribution.c', 'Storage.c', 'ASN1Message.c'],
        ]
        for cmd in commands:
            subprocess.run(cmd, check=True)


clean_engine()

asn_files_before_set = set(cfiles(ASN_DIR_GENERATED))

generate_files()

asn_files_after_set = set(sorted(cfiles(ASN_DIR_GENERATED)))
asn_diff = asn_files_after_set.difference(asn_files_before_set)
asn_files = sorted(asn_files_after_set)

with open(DEST_ASN_LIST, 'w') as asn_target_file:
    for asn_file in asn_files:
        item = '$(SRCROOT)/../../../asn.1/' + asn_file
        asn_target_file.write(item + '\n')

sync_files_after = sorted(cfiles(SYNC_DIR_GENERATED))

with open(DEST_SYNC_LIST, 'w') as sync_target_file:
    for sync_file in sync_files_after:
        item = '$(SRCROOT)/../src/' + sync_file
        sync_target_file.write(item + '\n')
