#!/usr/bin/env sh
set -exo

export LC_ALL=en_US.UTF-8

echo "INSTPREFIX=${INSTPREFIX}"
echo "BUILDROOT=${BUILDROOT}"

cat >local.conf <<'__LOCAL__'
PREFIX=${INSTPREFIX}
PER_MACHINE_DIRECTORY=${PEP_MACHINE_DIR}
YML2_PATH=${INSTPREFIX}/yml2
YML2_PROC=${INSTPREFIX}/yml2/yml2proc
ETPAN_LIB=-L${INSTPREFIX}/libetpan/lib
ETPAN_INC=-I${INSTPREFIX}/libetpan/include
ASN1C=${INSTPREFIX}/asn1c/bin/asn1c
ASN1C_INC=-I${INSTPREFIX}/asn1c/share/asn1c
OPENPGP=SEQUOIA
SEQUOIA_LIB=-L${INSTPREFIX}/lib
SEQUOIA_INC=-I${INSTPREFIX}/include
__LOCAL__

cat local.conf

export PKG_CONFIG_PATH=$INSTPREFIX/share/pkgconfig/
make clean
make
make install
