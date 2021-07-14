<!-- Copyright 2015-2017, pEp foundation, Switzerland
This file is part of the pEp Engine
This file may be used under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License
See CC_BY-SA.txt -->

# Build instructions for Debian 9

# Installing packaged dependencies

~~~
# general
apt install -y mercurial
# YML2
apt install -y python-lxml
# libetpan
apt install -y git build-essential automake libtool
# asn1c
apt install -y git build-essential automake libtool autoconf
# engine
apt install -y uuid-dev libgpgme-dev libsqlite3-dev sqlite3
~~~

# Installing unpackaged dependencies
## YML2

~~~
mkdir -p ~/code/yml2
git clone https://gitea.pep.foundation/fdik/yml2.git ~/code/yml2
~~~

## libetpan
pEp Engine requires libetpan with a set of patches that have not been upstreamed yet.

~~~
mkdir -p ~/code/libetpan

git clone https://gitea.pep.foundation/pEp.foundation/libetpan.git ~/code/libetpan
cd ~/code/libetpan
mkdir ~/code/libetpan/build
./autogen.sh --prefix="$HOME/code/libetpan/build"
make
make install
~~~

## asn1c

~~~
mkdir -p ~/code/asn1c
git clone git://github.com/vlm/asn1c.git ~/code/asn1c
cd ~/code/asn1c
git checkout tags/v0.9.28 -b pep-engine
autoreconf -iv
mkdir ~/code/asn1c/build
./configure --prefix="$HOME/code/asn1c/build"
make
make install
~~~

# pEp Engine

~~~
mkdir -p ~/code/pep-engine
hg clone https://pep.foundation/dev/repos/pEpEngine/ ~/code/pep-engine
cd ~/code/pep-engine
mkdir ~/code/pep-engine/build
~~~

Edit the build configuration to your needs in `Makefile.conf`, or create a `local.conf` that sets any of the make variables documented in `Makefile.conf`. All the default values for the build configuration variables on each platform are documented in `Makefile.conf`.

If a dependency is not found in your system's default include or library paths, you will have to specify the according paths in a make variable. Typically, this has to be done at least for YML2, libetpan and asn1c.

For a more detailed explanation of the mechanics of these build configuration files, and overriding defaults, see the comments in `Makefile.conf`.

Below is a sample `./local.conf` file, for orientation.

~~~
PREFIX=$(HOME)/code/pep-engine/build
PER_MACHINE_DIRECTORY=$(PREFIX)/share/pEp

YML2_PATH=$(HOME)/code/yml2

ETPAN_LIB=-L$(HOME)/code/libetpan/build/lib
ETPAN_INC=-I$(HOME)/code/libetpan/build/include

ASN1C=$(HOME)/code/asn1c/build/bin/asn1c
ASN1C_INC=-I$(HOME)/code/asn1c/build/share/asn1c
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
