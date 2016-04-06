p≡p Engine
==========

0. What it is
-------------

The p≡p engine is a Free Software library encapsulating implementations of:

- Key Management

  Key Management in p≡p engine is based on GnuPG key chains (NetPGP on iOS).
  Keys are stored in an OpenPGP compatbile format and can be used for different
  crypto implementations.

- Trust Rating

  p≡p engine is sporting a two phase trust rating system. In phase one there is
  a rating based on channel, crypto and key security named “comm_types”. In
  phase 2 these are mapped to user representable values which have attached
  colors to present them in traffic light semantics.

- Abstract Crypto API

  The Abstract Crypto API is providing functions to encrypt and decrypt data or
  full messages without requiring an application programmer to understand the
  different formats and standards.

- Message Transports

  p≡p engine will sport a growing list of Message Transports to support any
  widespread text messaging system including E-Mail, SMS, XMPP and many more.

p≡p engine is written in C99. It is not meant to be used in application code
directly. Instead, p≡p engine is coming together with a list of software
adapters for a variety of programming languages and development environments.

p≡p engine is under Gnu General Public License v3. If you want to use it under
a different license, please contact mailto:council@pep.foundation.


1. Dependencies
---------------

p≡p engine is depending on the following FOSS libraries:

libetpan, see https://github.com/fdik/libetpan
zlib, see http://zlib.net/
OpenSSL, see http://openssl.org/
iconv, see http://www.gnu.org/software/libiconv/
Cyrus SASL, see http://cyrusimap.org/
GnuPG via GPGME, see https://gnupg.org/
NetPGP/p≡p, see https://cacert.pep.foundation/dev/repos/netpgp-et/


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
	cat *.asc | gpg --import

