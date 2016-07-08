# Dependencies

You need a working [asn1c](https://lionet.info/asn1c/blog/).

```
brew install asn1c
```

# Building for OS X

* TODO: which dependencies can be fetched via "brew" and which have to be compiled manually?

## Build libetpan

```
cd pEpEngine   <--- huh? to build libetpan???
autoreconf -vfi
./configure
make
make install
```

# Building for iOS

This is done with Xcode. Simply add `pEpEngine.xcodeproj` to
your project and add a dependency to the target `pEpEngine`
(in `Target Dependencies` in your `Build Phases`.

Usually you just integrate `pEpiOSAdapter.xcodeproj`.
