#!/bin/bash
set -exuo pipefail

# ===========================
# Distro
# ===========================

echo 7 >"${INSTPREFIX}/D_REVISION"

D_REV=$(cat ${INSTPREFIX}/D_REVISION)
D=""

D=${INSTPREFIX}/out

mkdir -p ${INSTPREFIX}/out
rm -rf ${INSTPREFIX}/out/*
# pep  asn1c  capnp  cmake  curl  gmp  llvm  nettle  ninja  sequoia
# bin  include  lib  lib64  libexec  share
mkdir -p "$D"/{bin,ld,lib/pEp,share/pEp,include/pEp}

# Engine and below, and libpEpAdapter
cp -a ${INSTPREFIX}/lib/libpEpEngine.so "$D"/lib
cp -ar ${INSTPREFIX}/libetpan/lib/libetpan.so* "$D"/lib/pEp

cp -arv ${INSTPREFIX}/include/pEp/. "$D"/include/pEp

cp -arv ${PEP_MACHINE_DIR}/system.db "$D"/share/pEp

# Sequoia cmdline (optional above)
if [ -f ${INSTPREFIX}/bin/sq ] ; then
  cp -a ${INSTPREFIX}/lib/libsequoia_*.so* "$D"/lib/pEp
  cp -a ${INSTPREFIX}/bin/sq "$D"/bin
  cp -a ${INSTPREFIX}/bin/sqv "$D"/bin
  cp -arv ${INSTPREFIX}/lib/sequoia "$D"/lib/pEp/.
else
  cp -a ${INSTPREFIX}/lib/libsequoia_openpgp_ffi.* "$D"/lib/pEp
  cp -arv ${INSTPREFIX}/lib/sequoia "$D"/lib/pEp/.
fi

# versions
cp -a ${INSTPREFIX}/*.ver "$D"

find "$D"/lib -maxdepth 1 -type f -print -exec patchelf --set-rpath '$ORIGIN/pEp:$ORIGIN' {} \;
find "$D"/lib/pEp         -type f -print -exec patchelf --set-rpath '$ORIGIN' {} \;
find "$D"/bin -type f -print -exec patchelf --set-rpath '$ORIGIN/../lib/pEp:$ORIGIN/../lib' {} \;

ls -lh "$D"/*
du -sch "$D"
