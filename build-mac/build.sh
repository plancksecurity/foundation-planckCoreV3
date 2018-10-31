#!/bin/bash

# This file is under GNU General Public License 3.0
# see LICENSE.txt

#
# Invoke with `sh build.sh`
#

set -e

rm -f libcurl.a
rm -fr curl

wget https://curl.haxx.se/download/curl-7.48.0.tar.gz
gpg2 --verify curl-7.48.0.tar.gz.asc
tar xf curl-7.48.0.tar.gz
pushd curl-7.48.0
bash ../build_libcurl_dist.sh
popd
mv libcurl-ios-dist/lib/libcurl.a .

#exit 1

mv libcurl-ios-dist/include/curl .
rm -fr libcurl-ios-dist/
rm -fr curl-7.48.0
rm curl-7.48.0.tar.gz
