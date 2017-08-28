# this file is under Creative Commons License 3.0 cc-by-sa

1. Dependencies
---------------

p≡p engine is depending on the following FOSS libraries:

* a fork of libetpan, see https://github.com/fdik/libetpan
       git clone https://github.com/fdik/libetpan

* zlib, see http://zlib.net/
Oh yeah? Where?

* OpenSSL, see http://openssl.org/
Oh yeah? Where?

* iconv, see http://www.gnu.org/software/libiconv/

* Cyrus SASL, see http://cyrusimap.org/
Oh yeah? Where?

* One of the following OpenPGP implementations:
  * GnuPG via GPGME, version 1.6.0 or newer, see https://gnupg.org/
  * NetPGP/p≡p, see https://cacert.pep.foundation/dev/repos/netpgp-et/

* libcurl
Maybe on iOS?

SQlite3




compile-time dependencies:

* Asn1c, download from https://lionet.info/soft/asn1c-0.9.27.tar.gz . Debian 8's v0.9.24 does not work. Debian 9's v0.9.27 generates non-POSIX code, that will cause issues when the engine is compiled with '-std=c99'. Thus, use v0.9.28 for best results.

* yml2, which needs lxml (where to get?)

* One of the following build systems
  * GNU make
  * Visual Studio 2015


2. Building p≡p engine
----------------------

p≡p engine has an old style Makefile for building it.

The build is configured in Makefile.conf

It supports the common targets

$ make all
$ make install
$ make clean

and additionally

$ make package # for building a .tar.bz2 with the source distribution

On Windows, use Visual Studio.


3. How to cross-build
---------------------

For cross-building, BUILD_FOR is being used. I.e.:

$ BUILD_FOR=yourOS make -e


4. How to build the databases
-----------------------------

p≡p Engine uses two databases: ~/.pEp_management (on *NIX) or
%LOCALAPPDATA%\pEp\management.db on Windoze respectively, and
/usr/local/share/system.db on *NIX or %ALLUSERSPROFILE%\pEp\system.db
respectively. The latter contains the Trustwords dbs.

The managment db is being created by the first call of init() of p≡p Engine. It
does not need to be created manually. system.db is being created by using the
DDL in db/create_system_db.sql – the content is created by db/dic2csv.py
out of hunspell's dictionary packages (or something similar) and then being
imported using sqlite3's .import command. Dictionary files for different
languages are part of p≡p engine source distribution.

$ make db
$ make -C db install

You can test the Trustwords in system.db using db/trustwords.py
Both Python tools have a switch --help


5. How to run the tests
-----------------------

You have to import all the test keys into your local gpg instance:

	cd test
	cat 0x*.asc *_sec.asc| gpg --import

