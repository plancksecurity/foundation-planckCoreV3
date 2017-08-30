# Using NetPGP instead of GnuPG
## Prepare

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

## Build

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
