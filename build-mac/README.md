# BUILD-MACOS

Exists solely for sanity check.

pEpCC must run on all OSs, thus Xcode build is not suitable.

## Getting Dependencies

Install this …

```
sudo port install git

sudo port install gmake
sudo port install autoconf
sudo port install libtool
sudo port install automake
sudo port install asn1c
sudo port install wget
sudo port install gsed
pushd ~
git clone https://gitea.pep.foundation/fdik/yml2
popd
```

… and rust toolchain…

```
xcode-select --install
curl https://sh.rustup.rs -sSf | sh
```
add this to ~/.profile (or ~/.zprofile, depending on the shell you are using):
```
source $HOME/.cargo/env
export PATH="$HOME/.cargo/bin:$PATH"
```
restart your console and run:
```
sudo port install pkgconfig
rustup toolchain install nightly
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
rustup target add aarch64-apple-darwin --toolchain nightly
rustup update
```

… and etch this dependencies to be able to use build-mac

```
mkdir src_pEp4ipsec
cd src_pEp4ipsec

git clone https://gitea.pep.foundation/buff/mac-os-build-scripts-common-dependencies.git
git clone https://gitea.pep.foundation/pep.foundation/pEpObjCAdapter.git

http://pep-security.lu/gitlab/fdik/pEp-for-ipsec.git
```
## Build

### Using Xcode

open pEp-for-ipsec/pEpCC/Xcode/pEpCC.xcodeproj

Build scheme “pEpCC_macOS”.

### Using terminal

```
xcodebuild -project "pEp-for-ipsec/pEpCC/Xcode/pEpCC.xcodeproj" -scheme "pEpCC_macOS" -configuration [RELEASE|DEBUG]
```
