#!/usr/bin/env sh
set -exo

cat >local.conf <<__LOCAL__
PREFIX=${INSTPREFIX}
SQLITE3_FROM_OS=""
PER_MACHINE_DIRECTORY=${PEP_MACHINE_DIR}
YML2_PATH=${INSTPREFIX}/yml2
YML2_PROC=${INSTPREFIX}/yml2/yml2proc
ETPAN_LIB=-L${INSTPREFIX}/libetpan/lib
ETPAN_INC=-I${INSTPREFIX}/libetpan/include
ASN1C=${INSTPREFIX}/asn1c/bin/asn1c
ASN1C_INC=-I${INSTPREFIX}/asn1c/share/asn1c
OPENPGP=SEQUOIA
SEQUOIA_LDFLAGS=-L${INSTPREFIX}/lib
SEQUOIA_INC=-I${INSTPREFIX}/include
LDFLAGS  += -L${INSTPREFIX}/lib -L${INSTPREFIX}/libetpan/lib -L${INSTPREFIX}/pep/lib
GTEST_SRC_DIR=/usr/src/gtest
GTEST_PL=${BUILDROOT}/gtest-parallel/gtest_parallel.py

# Not sure if we want this: it should be considered.
# TRUSTWORDSXORCOMPATIBILITY = yes

# mostly for positron who wants to see what is failing on the CI machines and
# not on his system
LOGDESTINATIONS = PEP_LOG_DESTINATION_STDOUT
MAXLOGLEVEL = EVERYTHING
DEBUG = maintainer
__LOCAL__

cat local.conf
