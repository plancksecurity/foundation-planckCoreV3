#!/bin/sh

set -e
engine_dir="$1"

mkdir -p "$engine_dir/build-android/include/pEp"
cd "$engine_dir/src"
cp *.h "$engine_dir/build-android/include/pEp"

