This file is under Creative Commons License 3.0 cc-by-sa

# Building for OS X/macOS
See also README.txt for general information.

For compiling pEp Engine and its dependencies, make sure you have the LANG variable set. Some source files contain unicode characters, and python (assuming files are ascii) will fail.

```
export LANG=en_US.UTF-8
```

## Dependencies

### MacPorts
[Install MacPorts](https://www.macports.org/install.php) for your version of OS X/macOS.

If MacPorts is already installed on your machine, but was installed by a different user, make sure your `PATH` variable is set as follows in `~/.profile`:

```
export PATH="/opt/local/bin:/opt/local/sbin:$PATH"
```

Install dependencies packaged with MacPorts as follows.

```
sudo port install mercurial py27-lxml gpgme automake asn1c zlib openssl libiconv cyrus-sasl2
```

Make sure that `python` is a version 2 one:

```
sudo port select python python27
```

### NetPGP (if not GPGME)

#### Prepare :

Get OpenSSL and build/install it as shared library.

```
wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1u.tar.gz
tar xvfz openssl-1.0.1u.tar.gz
cd openssl-1.0.1u
./Configure darwin64-x86_64-cc --prefix=$HOME shared
make install
```

Get and autoconf NetPGP

```
cd $SRC
hg clone https://cacert.pep.foundation/dev/repos/netpgp-et/
cd netpgp-et
autoreconf -i
```

#### Build

Important : LDFLAGS is set to help finding OpenSSL shared lib. If not set,
system's default libcrypto may silently be used instead, causing memory
corruption or crash at runtime.

```
mkdir netpgp_debug
cd netpgp_debug
$SRC/netpgp-et/configure --with-openssl=$HOME --prefix=$HOME CPPFLAGS=-DDEBUG CXXFLAGS="-g -O0" LDFLAGS="-L${HOME}/lib"
make
make install
```

### Other Dependecies

#### [yml2](https://fdik.org/yml/toolchain)
Install into your home directory:

```
pushd ~
hg clone https://cacert.pep.foundation/dev/repos/yml2/
popd
```

#### libetpan

Note: libetpan needs libz and libiconv, but the libiconv from MacPorts is not compatible, some
functions seem to have been renamed there. Therefore the dynlib from OS X is used.

```
git clone https://github.com/fdik/libetpan
cd libetpan
./autogen.sh --prefix "$HOME"
make
make install
```

## Building pEp Engine

### Configuration
You can change some defaults by editing `Makefile.conf`. The following variable needs to be set appropriately:

```
LIBGPGME=/opt/local/lib/libgpgme.11.dylib
```

### Build

```
make clean
make all
make db
```

### Installation

```
make install
sudo make -C db install
```

Since the `system.db` rarely changes, the last step is not needed for every build. If you would like to be able to install the engine without `sudo`, ensure that your user can write the file `/usr/local/share/pEp/system.db`. This is not recommended for production machines.

### Run tests

If you installed the test keys in your keyring (see: README.txt), this should just work:

```
make test
```

# Building for iOS

This is done with Xcode. Simply add `pEpEngine.xcodeproj` to
your project and add a dependency to the target `pEpEngine`
(in `Target Dependencies` in your `Build Phases`.

Usually you just integrate `pEpiOSAdapter.xcodeproj`.
