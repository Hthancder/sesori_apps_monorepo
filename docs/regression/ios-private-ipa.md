# Private iOS IPA export

## Supported behavior

`Build private iOS IPA` is a manually dispatched GitHub Actions workflow. It
builds the actual Flutter phone app using the repository's pinned toolchain,
existing UI, authentication, encrypted relay and OpenCode 2 client contracts.
It does not sign, upload to TestFlight, change a running bridge, or require
Sesori's Apple/signing/attribution secrets. Attribution keys remain absent.

The artifact contains an unsigned IPA, `SHA256SUMS` and `build-info.json` with
the source commit, Actions run, bundle versions, native inventory and explicit
unverified device-installation status. Downloads require GitHub login and
expire after 30 days. This workflow does not create a public release.

The packaging boundary rejects simulator builds, missing Flutter binaries or
assets, binaries without arm64, and runtime bundle minimum OS declarations above 15.0.
Frameworks whose executable is a static archive (`!<arch>`), including a
universal FAT32/FAT64 wrapper containing only static-archive slices, are link-time inputs,
not iOS runtime frameworks; the export omits those framework directories and
records them in `excludedStaticFrameworks`. The original build is not modified,
separate resource bundles remain, and runtime framework checks are not relaxed.
Static exclusion follows Apple TN2435, "Embedded Static Libraries"; it must not
be inferred from the library's source package or name.
Mixed, dynamic, truncated or out-of-bounds universal slices do not qualify for
this exclusion. Required Runner/App/Flutter binaries cannot be static archives.

The inspected Xcode build also embeds four empty analytics dylib stubs with
an iOS `100.0` declaration: FirebaseAnalytics, GoogleAdsOnDeviceConversion,
GoogleAppMeasurement and GoogleAppMeasurementIdentitySupport. Only those exact
names can qualify for a separate exclusion, after checking their actual arm64
Mach-O load commands, zero-sized text, zero symbols and empty exports. Every
remaining native binary is inspected for load dependencies before export; a
reference to a candidate stub rejects the export instead of dropping a runtime
dependency. Unknown, code-bearing or referenced dylibs retain the iOS 15 gate.
Omissions appear in `excludedEmptyStubFrameworks`, separately from static
archives. Neither original binaries nor their deployment metadata are rewritten.

It refuses to overwrite an existing output directory. Tests use tiny fixture
bundles only; the delivered artifact must come from `flutter build ios`.

## Coverage

| Level | Boundary | Required result |
|---|---|---|
| L1 | Automated | Run `python3 -m unittest discover -s .github/scripts -p test_package_ios_ipa.py -v`; the CLI produces a correct Payload archive, executable modes and checksum, and rejects invalid inputs. |
| L2 | Packaged / GitHub | Dispatch `.github/workflows/build-ios-ipa.yml`; require a successful real iOS build, completed artifact upload, full source commit and a working artifact link. Read the downloaded checksum and provenance; a green fixture test alone is insufficient. |
| L3 | Client end to end / iPhone | Install using a compatible signing/jailbreak installer, then check login, existing projects/sessions, OpenCode 2 streaming, tools/questions/permissions, reconnect and background/foreground. Installation and APNs depend on the actual signing/entitlements; an unsigned ZIP does not prove them. |
| L4 | Client end to end | Repeat active streaming across a network interruption and a bridge reconnect without duplicate prompts or lost history. |
| L5 | No additional coverage | Lower levels remain applicable. |

Device checks belong to the device owner when the build operator has no phone
access. Keep them explicitly unverified until observed; iOS 15 declarations do
not alone establish runtime compatibility of every native library.
