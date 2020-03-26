<!-- Copyright 2015-2017, pEp foundation, Switzerland
This file is part of the pEp Engine
This file may be used under the terms of the Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0) License
See CC_BY-SA.txt -->

# Build instructions for macOS Sierra

# Installing packaged dependencies
You will find instructions for using either Macports or Homebrew below to install the compile-time dependencies.

## MacPorts
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

Ensure that `python` is Python 2.7:

~~~
sudo port select python python27
~~~

## Homebrew
Install Homebrew according to the instructions found [here](https://docs.brew.sh/Installation.html).
Ensure that Homebrew's binary path (`/usr/local/bin`) is in your `PATH` environment variable.

~~~
# general
brew install mercurial
# YML2
# If you don't have pip with your Python 2 distribution, you can install it with brew
brew install python
pip2 install --user lxml
# libetpan
brew install git autoconf automake libtool
# asn1c
brew install asn1c
# engine
brew install gpgme
~~~

# Installing unpackaged dependencies
## YML2
To check if lxml is properly installed, you can use this lxml "hello world" command:

~~~
python2 -c 'from lxml import etree; root = etree.Element("root"); print(root.tag)'
~~~

It should generate the following output:

~~~
root
~~~

~~~
mkdir -p ~/code/yml2
hg clone https://pep.foundation/dev/repos/yml2/ ~/code/yml2
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

It's of course possible to skip MacPort's version, and use a self-compiled GPGME/GPG. The default build configuration assumes this case, and assumes you have installed your GPGME with `$(HOME)` as your prefix.

# pEp Engine

~~~
mkdir -p ~/code/pep-engine
hg clone https://pep.foundation/dev/repos/pEpEngine/ ~/code/pep-engine
cd ~/code/pep-engine
mkdir ~/code/pep-engine/build
~~~

Edit the build configuration to your needs in `Makefile.conf`, or create a `local.conf` that sets any of the make variables documented in `Makefile.conf`. All the default values for the build configuration variables on each platform are documented in `Makefile.conf`.

If a dependency is not found in your system's default include or library paths, you will have to specify the according paths in a make variable. Typically, this has to be done at least for YML2, and libetpan.

For a more detailed explanation of the mechanics of these build configuration files, and overriding defaults, see the comments in `Makefile.conf`.

Below is a sample `./local.conf` file, for orientation.

~~~
PREFIX=$(HOME)/code/engine/build
PER_MACHINE_DIRECTORY=$(PREFIX)/share/pEp

YML2_PATH=$(HOME)/code/yml2

ETPAN_LIB=-L$(HOME)/code/libetpan/build/lib
ETPAN_INC=-I$(HOME)/code/libetpan/build/include

GPGME_LIB=-L$(HOME)/lib
GPGME_INC=-I$(HOME)/include
~~~

The engine is built as follows:

~~~
make all
make db
~~~

If your build fails with an error message similar to the following:

~~~
  File "/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/locale.py", line 477, in _parse_localename
    raise ValueError, 'unknown locale: %s' % localename
ValueError: unknown locale: UTF-8
~~~

or any other locale-related Python error, make sure Python does not have any locale-related environment variables set.
Usually, `unset LC_CTYPE` is sufficient to take care of the problem, but it depends on your macOS's regional and language settings and which terminal emulator you use.
This is a bug in Python, see [https://bugs.python.org/issue18378#msg215215](https://bugs.python.org/issue18378#msg215215).

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
