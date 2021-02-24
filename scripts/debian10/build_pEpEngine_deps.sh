#!/usr/bin/env sh
set -exo

### YML2
cd $INSTPREFIX
wget https://fdik.org/yml2.tar.bz2
tar -xf yml2.tar.bz2
rm yml2.tar.bz2


### libetpan
git clone https://github.com/fdik/libetpan $BUILDROOT/libetpan
cd $BUILDROOT/libetpan
test -f configure || NOCONFIGURE=absolutely ./autogen.sh
./configure --prefix=${INSTPREFIX}/libetpan \
    --without-openssl --without-gnutls --without-sasl \
    --without-curl --without-expat --without-zlib \
    --disable-dependency-tracking
make -j$(nproc)
make install
echo "${libetpan_ver}">${INSTPREFIX}/libetpan.ver


### ASN1c
git clone https://github.com/vlm/asn1c.git $BUILDROOT/asn1c
cd $BUILDROOT/asn1c
git checkout tags/v0.9.28 -b pep-engine
test -f configure || autoreconf -iv
./configure --prefix=${INSTPREFIX}/asn1c
make -j$(nproc) && make install
echo "${asn1c_ver}">${INSTPREFIX}/asn1c.ver
