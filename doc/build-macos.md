<!-- Copyright 2015-2017, pEp foundation, Switzerland
This file is part of the pEp Engine
This file may be used under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License
See CC_BY-SA.txt -->

# Build instructions for macOS Sierra and iOS

# Installing packaged dependencies

## MacPorts

MacPorts is needed to install some compile-time dependencies.
Install MacPorts according to the instructions found [here](https://www.macports.org/install.php).
Ensure that Macports' binary paths (`/opt/local/bin` and `/opt/local/sbin`) are in your `PATH` environment variable.

~~~
# general
sudo port install mercurial
# YML2
sudo port install py27-lxml
# libetpan
sudo port install git autoconf automake libtool
# asn1c
sudo port install asn1c
# engine
sudo port install gpgme
~~~

FIXME Are `zlib openssl cyrus-sasl2` needed? They were in an older revision of the instructions

Ensure that `python` is Python 2.7:

~~~
sudo port select python python27
~~~

# Installing unpackaged dependencies
## YML2

~~~
mkdir -p ~/code/yml2
hg clone https://cacert.pep.foundation/dev/repos/yml2/ ~/code/yml2
~~~

## libetpan
pEp Engine requires libetpan with a set of patches that have not been upstreamed yet.

~~~
mkdir -p ~/code/libetpan
git clone https://github.com/fdik/libetpan ~/code/libetpan
cd ~/code/libetpan
mkdir ~/code/libetpan/build
./autogen.sh --prefix="$HOME/code/libetpan/build"
make
make install
~~~

## GPGME
The MacPorts-packaged GPGME links to a version of GNU libiconv that has files in the same include/library paths as GPGME. This version of libiconv must not be visible to the linker when the pEp Engine is build or run.

Thus the files of the GPGME distribution will have to be manually copied to separate include/library folders, so that no include or library paths used for building the pEp Engine contains files of MacPorts' libiconv distribution.

~~~
mkdir -p ~/code/gpgme/build/include
cp /opt/local/include/gpg*.h ~/code/gpgme/build/include
mkdir -p ~/code/gpgme/build/lib
cp -r /opt/local/lib/libgpg* ~/code/gpgme/build/lib
~~~

It's of course possible to skip MacPort's version, and use a self-compiled GPGME/GPG.

# pEp Engine

~~~
mkdir -p ~/code/pep-engine
hg clone https://cacert.pep.foundation/dev/repos/pEpEngine/ ~/code/pep-engine
cd ~/code/pep-engine
mkdir ~/code/pep-engine/build
~~~

For an explanation of the mechanics of `PLATFORM_OVERRIDE`, see the inline comments in `Makefile.conf`.
In this guide, the platform-specific configuration will be called `local`.
The installation directory will be a subdirectory of the repository.
This is useful for testing only.

~~~
export PLATFORM_OVERRIDE=local
~~~

`./build-config/local.conf`:

~~~
PREFIX=$(HOME)/code/pep-engine/build
SYSTEM_DB=$(PREFIX)/share/pEp/system.db

YML2_PATH=$(HOME)/code/yml2

ETPAN_LIB=-L$(HOME)/code/libetpan/build/lib
ETPAN_INC=-I$(HOME)/code/libetpan/build/include

GPGME_LIB=-L$(HOME)/code/gpgme/build/lib
GPGME_INC=-I$(HOME)/code/gpgme/build/include
~~~

The engine is built as follows:

~~~
make all
make db
~~~

The unit tests can be run without the engine library being installed, however the `system.db` must be installed:

~~~
make -C db install
~~~

Since `system.db` rarely changes, its installation is not needed for every build.

Tests can be compiled and executed with the following commands:

~~~
make -C test compile
make test
~~~
