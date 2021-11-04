<!-- Copyright 2015-2021, pEp foundation, Switzerland
This file is part of the pEp Engine
This file may be used under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License
See CC_BY-SA.txt -->

# Build instructions for Debian 9 and 10

We assume the user keeps sources under `~/pep-src`.  There is no single
installation prefix: each package is built, or when supported installed, in
either its source directory or in a subdirectory of its source directory.
Rationale: we do not pollute the user system, uninstalling is trivial.

This is Unix: we assume no spaces in user names.

~~~
mkdir -p ~/pep-src
~~~

# Installing packaged dependencies

~~~
# general
apt install -y git
# libetpan
apt install -y git build-essential automake libtool
# asn1c
apt install -y git build-essential automake libtool autoconf
# sequoia
apt install git rustc cargo clang libclang-dev make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev
# engine
apt install -y uuid-dev libgpgme-dev libsqlite3-dev sqlite3
# optional: developer documentation
apt install -y doxygen pandoc
~~~

# Installing unpackaged dependencies
## YML2

~~~
mkdir -p ~/pep-src/yml2
git clone https://gitea.pep.foundation/fdik/yml2.git ~/pep-src/yml2
~~~

## libetpan
pEp Engine requires libetpan with a set of patches that have not been upstreamed yet.

~~~
mkdir -p ~/pep-src/libetpan

git clone https://gitea.pep.foundation/pEp.foundation/libetpan.git ~/pep-src/libetpan
cd ~/pep-src/libetpan
mkdir ~/pep-src/libetpan/build
./autogen.sh --prefix="$HOME/pep-src/libetpan/build"
make
make install
~~~

## asn1c

~~~
mkdir -p ~/pep-src/asn1c
git clone git://github.com/vlm/asn1c.git ~/pep-src/asn1c
cd ~/pep-src/asn1c
git checkout tags/v0.9.28 -b pep-engine
autoreconf -iv
mkdir ~/pep-src/asn1c/build
./configure --prefix="$HOME/pep-src/asn1c/build"
make
make install
~~~

## sequoia

~~~
git clone https://gitlab.com/sequoia-pgp/sequoia
cd ~/pep-src/sequoia
git checkout openpgp/v1.3.0
# Make an optimised sequoia build.
cargo build --all --release -j16
~~~

This alternative for the last line above is faster, but generates compiled libraries
in `~/pep-src/sequoia/target/debug` instead of `~/pep-src/sequoia/target/release`:
several definitions below need to be adapted.
~~~
# Alternative: make a debugging sequoia build.
cargo build --all -j16
~~~

# pEp Engine

~~~
mkdir -p ~/pep-src/pep-engine
git clone https://gitea.pep.foundation/pEp.foundation/pEpEngine ~/pep-src/pep-engine
cd ~/pep-src/pep-engine
mkdir build
~~~

Edit the build configuration to your needs in `Makefile.conf`, or create a `local.conf` in your source directory (the same containing `Makefile.conf`) that sets any of the make variables documented in `Makefile.conf`. All the default values for the build configuration variables on each platform are documented in `Makefile.conf`.

If a dependency is not found in your system's default include or library paths, you will have to specify the according paths in a make variable. Typically, this has to be done at least for YML2, libetpan and asn1c.

For a more detailed explanation of the mechanics of these build configuration files, and overriding defaults, see the comments in `Makefile.conf`.

The following `./local.conf` example should work in the configuration described here.

~~~
PREFIX=$(HOME)/pep-src/pep-engine/build
PER_MACHINE_DIRECTORY=$(PREFIX)/share/pEp

YML2_PATH=$(HOME)/pep-src/yml2

ETPAN_LIB=-L$(HOME)/pep-src/libetpan/build/lib
ETPAN_INC=-I$(HOME)/pep-src/libetpan/build/include

ASN1C=$(HOME)/pep-src/asn1c/build/bin/asn1c
ASN1C_INC=-I$(HOME)/pep-src/asn1c/build/share/asn1c

SEQUOIA_INC=-I$(HOME)/pep-src/sequoia/openpgp-ffi/include
SEQUOIA_LDFLAGS=-L$(HOME)/pep-src/sequoia/target/release

GTEST_SRC_DIR=$(HOME)/pep-src/googletest/googletest
GTEST_INC_DIR=$(HOME)/pep-src/googletest/googletest/include
GTEST_PL=$(HOME)/pep-src/gtest-parallel/gtest_parallel.py
~~~

The engine is built as follows:

~~~
make all
make db
~~~

The unit tests can be run without the engine library being installed, however `system.db` must be installed:

~~~
make -C db install
~~~

Since `system.db` rarely changes, its installation is not needed for every build.

Tests can be compiled and executed with the following commands:

~~~
make -C test compile
make test
~~~
