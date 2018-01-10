# -*- coding: utf-8 -*-

# this file is under GNU General Public License 3.0
# Copyleft 2017, p≡p foundation


from setup_test import create_homes


def pytest_runtest_setup(item):
    try:
        create_homes()
    except FileExistsError: # if concurrent process is already creating things
        pass
