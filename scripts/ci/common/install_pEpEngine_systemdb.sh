#!/usr/bin/env sh
set -exo

# Install systemdb (need to be root depending on the path)
cd $BUILDROOT/pEpEngine
export LC_ALL=en_US.UTF-8
export PKG_CONFIG_PATH=$INSTPREFIX/share/pkgconfig/
echo "Setup DB"
make -C db install
