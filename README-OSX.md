# Building for OS X/macOS

See also README.txt for general information.

## Environment

`export LANG=en_US.UTF-8` is recommended on OS X.

## Dependencies

### MacPorts

Install [MacPorts](https://www.macports.org/) for your
[version of OS X/macOS](https://www.macports.org/install.php).

Note that you need [Xcode installed](https://www.macports.org/install.php)
for MacPorts, and for building the engine. You also need to accept Xcode's EULA.

#### MacPorts dependencies

```
sudo port install mercurial
sudo port install py27-lxml
sudo port install gpgme
sudo port install automake
sudo port install asn1c
sudo port install zlib
```

There are others, please refer to the engine README.txt.

Make sure that `python` is a version 2 one:

```
sudo port select python python27
```

### Other dependecies

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
git clone https://github.com/fdik/libetpan libetpan-osx
cd libetpan-osx/
./autogen.sh
make
cp ./src/.libs/libetpan.a ~/lib/
```

### Configuration

You can change some defaults by editing `Makefile.conf`. But this readme assumes you don't.

### Build

```
make clean
make all
make db
```

Done! The result should be (among others):

```
./src/libpEpEngine.a
./src/libpEpEngine.dylib
```

### Install

Install (you might need sudo for some commands, depending on how your system is set up):

```
make install
make -C db install
```

Since the `system.db` rarely changes, `make -C db install` is not needed for every build.

### Run tests

If you installed the test keys in your keyring (README.txt),
this should just work:

```
make test
```

# Building for iOS

This is done with Xcode. Simply add `pEpEngine.xcodeproj` to
your project and add a dependency to the target `pEpEngine`
(in `Target Dependencies` in your `Build Phases`.

Usually you just integrate `pEpiOSAdapter.xcodeproj`.
