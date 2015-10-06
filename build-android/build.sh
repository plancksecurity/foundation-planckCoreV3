#!/bin/sh

set -e

build_version=1
ANDROID_PLATFORM=android-21
openssl_build_version=1
cyrus_sasl_build_version=1
libetpan_build_version=1
archs="armeabi armeabi-v7a x86 x86_64"
package_name=pEpEngine-android

current_dir="`pwd`"

if test "x$ANDROID_NDK" = x ; then
  echo should set ANDROID_NDK before running this script.
  exit 1
fi

if test "x$GPGME_INCLUDE_PATH" = x ; then
  echo should set GPGME_INCLUDE_PATH before running this script.
  exit 1
fi

if test "x$LIBETPAN_PATH" = x ; then
  echo should set LIBETPAN_PATH before running this script.
  exit 1
fi

libetpan_dir=$LIBETPAN_PATH

function build {
  rm -rf "$current_dir/obj"
  
  cd "$current_dir/jni"
  $ANDROID_NDK/ndk-build V=1 TARGET_PLATFORM=$ANDROID_PLATFORM TARGET_ARCH_ABI=$TARGET_ARCH_ABI \
    OPENSSL_PATH="$current_dir/third-party/openssl-android-$openssl_build_version" \
    CYRUS_SASL_PATH="$current_dir/third-party/cyrus-sasl-android-$cyrus_sasl_build_version" \
    LIBETPAN_PATH="$current_dir/third-party/libetpan-android-$libetpan_build_version"

  mkdir -p "$current_dir/$package_name-$build_version/libs/$TARGET_ARCH_ABI"
  cp "$current_dir/obj/local/$TARGET_ARCH_ABI/libpEpEngine.a" "$current_dir/$package_name-$build_version/libs/$TARGET_ARCH_ABI"
  rm -rf "$current_dir/obj"
}

mkdir -p "$current_dir/third-party"
cd "$current_dir/third-party"
unzip -qo "$libetpan_dir/dependencies/openssl/openssl-android-$openssl_build_version.zip"
unzip -qo "$libetpan_dir/dependencies/cyrus-sasl/cyrus-sasl-android-$cyrus_sasl_build_version.zip"
unzip -qo "$libetpan_dir/libetpan-android-$libetpan_build_version.zip"

# Copy public headers to include
mkdir -p "$current_dir/$package_name-$build_version/include/pEp"
cd "$current_dir/../src"
cp *.h "$current_dir/$package_name-$build_version/include/pEp"

# Start building.
for arch in $archs ; do
  TARGET_ARCH_ABI=$arch
  build
done

rm -rf "$current_dir/third-party"
cd "$current_dir"
zip -qry "$package_name-$build_version.zip" "$package_name-$build_version"
rm -rf "$package_name-$build_version"
