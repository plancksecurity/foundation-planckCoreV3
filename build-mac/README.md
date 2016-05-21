# Building for iOS

This is done with Xcode. Simply add `pEpEngine.xcodeproj` to
your project and add a dependency to the target `pEpEngine`
(in `Target Dependencies` in your `Build Phases`.

Usually you just integrate `pEpiOSAdapter.xcodeproj`.

## Dependencies

You need a working [asn1c](https://lionet.info/asn1c/blog/).

```
brew install asn1c
```
