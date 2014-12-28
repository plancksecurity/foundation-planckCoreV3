pEp Engine
==========

0. What it is and building it
-----------------------------

The pEp Engine encapsulates all real functionality of pEp.
It has an old style Makefile for building it.

The build is configured in Makefile.conf

It supports the common targets

$ make all
$ make install
$ make clean

and additionally

$ make package # for building a .tar.bz2 with the source distribution

To build on platforms without uname(1) use BUILD_ON:

C:\pEpEngine> :for building a .zip with a binary distribution
C:\pEpEngine> set BUILD_ON=Windoze && make -e windist

1. How to cross-build
---------------------

For cross-building, BUILD_FOR is being used. I.e.:

$ BUILD_FOR=Windoze make -e windist

Supported platforms are Darwin, Windoze, Linux.

1. a) Cross-building for Windoze
................................

Cross-building for Windoze requires mingw-w64.

Easier linking to Visual Studio can be achieved by using Microsoft's LIB.EXE
tool; this command created the needed pEpEngine.lib import library:

C:\pEpEngine> lib /def:pEpEngine.def

2. How to build the databases
-----------------------------

pEp Engine uses two databases: ~/.pEp_management (on *NIX) or
%LOCALAPPDATA%\pEp\management.db on Windoze respectively, and
/usr/local/share/system.db on *NIX or %ALLUSERSPROFILE%\pEp\system.db
respectively. The latter contains the safewords dbs.

The managment db is being created by the first call of init() of pEp Engine. It
does not need to be created manually. system.db is being created by using the
DDL in db/create_system_db.sql – the content is created by db/dic2csv.py
out of hunspell's dictionary packages (or something similar) and then being
imported using sqlite3's .import command.

You can test the safewords in system.db using db/safewords.py
Both Python tools have a switch --help

