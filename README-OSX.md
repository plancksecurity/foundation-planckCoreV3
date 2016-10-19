# Building for OS X/macOS

See also README.txt for general information.

## Dependencies

### MacPorts

Install [MacPorts](https://www.macports.org/) for your
[version of OS X/macOS](https://www.macports.org/install.php).

Note that you need [Xcode installed](https://www.macports.org/install.php)
for MacPorts, and for building the engine. You also need to accept Xcode's EULA.

*Note*: Use the script `macports_env.sh` (or a similar one) to set up a clean build environment
before building the engine:

```
. macports_env.sh
```

If you don't use that environment, please make sure you've set up all search paths correctly.

#### MacPorts dependencies

```
sudo port install mercurial
sudo port install py27-lxml
sudo port install gpgme
sudo port install automake
sudo port install asn1c
sudo port install zlib
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

##### libetpan with xcodebuild

The build with autoconf (see previous section) is preferred. This is just for completeness.
*Don't actually build libetpan with xcodebuild.*

```
git clone https://github.com/fdik/libetpan libetpan-osx
cd libetpan-osx/build-mac
xcodebuild -project libetpan.xcodeproj/ -target "static libetpan"
mkdir ~/lib
cp build/Release/libetpan.a ~/lib/
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

Make sure that you add `/opt/local/lib` to each definition of `LD_LIBRARY_PATH`
in `test/Makefile`. This ensures that libgpgme will be found:

```
test: pEpEngineTest
        LD_LIBRARY_PATH=/opt/local/lib:~/lib:../src ./pEpEngineTest
```

```
make test
```

# Building for iOS

This is done with Xcode. Simply add `pEpEngine.xcodeproj` to
your project and add a dependency to the target `pEpEngine`
(in `Target Dependencies` in your `Build Phases`.

Usually you just integrate `pEpiOSAdapter.xcodeproj`.
