#!/usr/bin/env sh
set -exo

### YML2
cd $INSTPREFIX
curl -O "https://gitea.pep.foundation/fdik/yml2/archive/${YML2_VERSION}.tar.gz"
tar -xf "${YML2_VERSION}.tar.gz"
rm -f ${YML2_VERSION}.tar*


### libetpan
git clone https://gitea.pep.foundation/pEp.foundation/libetpan $BUILDROOT/libetpan
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
