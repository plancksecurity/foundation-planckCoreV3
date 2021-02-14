#!/usr/bin/env sh
set -exo

export LC_ALL=en_US.UTF-8

cat >local.conf <<__LOCAL__
PREFIX=${INSTPREFIX}
SQLITE3_FROM_OS=""
PER_MACHINE_DIRECTORY=${PEP_MACHINE_DIR}
YML2_PATH=${BUILDROOT}/yml2
YML2_PROC=${BUILDROOT}/yml2/yml2proc
ETPAN_LIB=-L${INSTPREFIX}/libetpan/lib
ETPAN_INC=-I${INSTPREFIX}/libetpan/include
ASN1C=${INSTPREFIX}/asn1c/bin/asn1c
ASN1C_INC=-I${INSTPREFIX}/asn1c/share/asn1c
OPENPGP=SEQUOIA
SEQUOIA_LIB=-L${INSTPREFIX}/lib
SEQUOIA_INC=-I${INSTPREFIX}/include
LDFLAGS  += -L${INSTPREFIX}/lib -L${INSTPREFIX}/libetpan/lib -L${INSTPREFIX}/pep/lib -nostartfiles
__LOCAL__

cat local.conf

export PKG_CONFIG_PATH=$INSTPREFIX/share/pkgconfig/
make all && make db && make install
