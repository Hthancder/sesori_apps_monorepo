import hashlib
import json
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("package_ios_ipa.py")
COMMIT = "1234567890abcdef1234567890abcdef12345678"
RUN_URL = "https://github.com/Hthancder/sesori_apps_monorepo/actions/runs/123"


class IosIpaPackagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ios ipa ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.app = self.root / "Runner.app"
        self.output = self.root / "output"
        self.info = {
            "CFBundleExecutable": "Runner",
            "CFBundleIdentifier": "com.sesori.app",
            "CFBundleShortVersionString": "1.16.0",
            "CFBundleVersion": "12",
            "MinimumOSVersion": "15.0",
            "DTPlatformName": "iphoneos",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        }
        self.write_plist(self.app / "Info.plist", self.info)
        self.write_binary(self.app / "Runner")
        for name in ("App", "Flutter"):
            framework = self.app / "Frameworks" / f"{name}.framework"
            self.write_binary(framework / name)
            self.write_plist(framework / "Info.plist", {
                "CFBundleExecutable": name, "MinimumOSVersion": "15.0",
            })
        assets = self.app / "Frameworks/App.framework/flutter_assets"
        assets.mkdir()
        (assets / "AssetManifest.bin").write_bytes(b"fixture assets")

    @staticmethod
    def write_plist(path, info):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(info))

    @staticmethod
    def write_binary(path, cpu=0x0100000C):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(struct.pack("<8I", 0xFEEDFACF, cpu, 0, 2, 0, 0, 0, 0))
        path.chmod(0o755)

    @staticmethod
    def universal_binary(*slices, wide=False):
        magic = 0xCAFEBABF if wide else 0xCAFEBABE
        result = bytearray(struct.pack(">II", magic, len(slices)))
        for index, data in enumerate(slices):
            offset = 4096 * (index + 1)
            if wide:
                result.extend(struct.pack(">IIQQII", 0x0100000C, index, offset, len(data), 12, 0))
            else:
                result.extend(struct.pack(">IIIII", 0x0100000C, index, offset, len(data), 12))
        for index, data in enumerate(slices):
            result.extend(bytes(4096 * (index + 1) - len(result)))
            result.extend(data)
        return bytes(result)

    def run_packager(self):
        return subprocess.run([
            sys.executable, str(SCRIPT), "--app", str(self.app),
            "--output", str(self.output), "--commit", COMMIT, "--run-url", RUN_URL,
        ], capture_output=True, text=True)

    @staticmethod
    def dylib_command(name):
        value = name.encode() + b"\0"
        size = (24 + len(value) + 7) // 8 * 8
        return struct.pack("<6I", 0xC, size, 24, 2, 0, 0) + value.ljust(size - 24, b"\0")

    @staticmethod
    def empty_analytics_stub(name, *, code_size=0):
        # The actual failing runner emits a dylib with empty __text, no symbols,
        # an iOS 100 deployment command, and only a libSystem dependency.
        section = struct.pack("<16s16sQQ8I", b"__text", b"__TEXT", 4096,
                              code_size, 4096, 0, 0, 0, 0x80000400, 0, 0, 0)
        segment = struct.pack("<II16sQQQQ4I", 0x19, 152, b"__TEXT", 0, 4096,
                              0, 4096, 5, 5, 1, 0) + section
        linkedit = struct.pack("<II16sQQQQ4I", 0x19, 72, b"__LINKEDIT",
                               4096, 4096, 4096, 8, 1, 1, 0, 0)
        install_name = IosIpaPackagingTests.dylib_command(f"@rpath/{name}.framework/{name}")
        install_name = struct.pack("<I", 0xD) + install_name[4:]
        commands = [segment, linkedit, install_name,
                    struct.pack("<6I", 2, 24, 4096, 0, 4096, 8),
                    struct.pack("<6I", 0x32, 24, 2, 100 << 16, 27 << 16, 0),
                    struct.pack("<4I", 0x80000033, 16, 4096, 8),
                    IosIpaPackagingTests.dylib_command("/usr/lib/libSystem.B.dylib")]
        payload = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 6,
                              len(commands), sum(map(len, commands)), 0, 0) + b"".join(commands)
        return payload.ljust(4096, b"\0") + bytes(8)

    def test_omits_only_unreferenced_empty_analytics_stubs_and_discloses_them(self):
        name = "FirebaseAnalytics"
        framework = self.app / f"Frameworks/{name}.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": name, "MinimumOSVersion": "100.0",
        })
        binary = self.universal_binary(self.empty_analytics_stub(name))
        (framework / name).write_bytes(binary)
        result = self.run_packager()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.output / "build-info.json").read_text())
        self.assertEqual(report["excludedEmptyStubFrameworks"], [f"Frameworks/{name}.framework"])
        self.assertEqual(report["excludedStaticFrameworks"], [])
        with zipfile.ZipFile(self.output / report["artifact"]) as archive:
            self.assertFalse(any(f"{name}.framework" in path for path in archive.namelist()))
            self.assertIn("Payload/Runner.app/Frameworks/App.framework/App", archive.namelist())
        self.assertEqual((framework / name).read_bytes(), binary)
        self.assertEqual(plistlib.loads((framework / "Info.plist").read_bytes())["MinimumOSVersion"], "100.0")

    def test_rejects_referenced_or_code_bearing_analytics_stubs_before_export(self):
        name = "FirebaseAnalytics"
        framework = self.app / f"Frameworks/{name}.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": name, "MinimumOSVersion": "100.0",
        })
        command = self.dylib_command(f"@rpath/{name}.framework/{name}")
        consumer = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2,
                               1, len(command), 0, 0) + command
        for relative in ("Runner", "Frameworks/App.framework/App"):
            with self.subTest(consumer=relative):
                path = self.app / relative
                original = path.read_bytes()
                path.write_bytes(consumer)
                (framework / name).write_bytes(self.empty_analytics_stub(name))
                result = self.run_packager()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("iOS 15", result.stderr)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)
        (framework / name).write_bytes(self.empty_analytics_stub(name, code_size=4))
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iOS 15", result.stderr)
        self.assertFalse(self.output.exists())

    def test_cli_exports_real_payload_with_modes_checksum_and_honest_provenance(self):
        result = self.run_packager()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ipa = self.output / "Sesori-ios-1.16.0-12-unsigned.ipa"
        with zipfile.ZipFile(ipa) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn("Payload/Runner.app/Frameworks/App.framework/App", archive.namelist())
            self.assertIn("Payload/Runner.app/Frameworks/Flutter.framework/Flutter", archive.namelist())
            self.assertEqual(archive.read("Payload/Runner.app/Frameworks/App.framework/flutter_assets/AssetManifest.bin"),
                             b"fixture assets")
            executable = archive.getinfo("Payload/Runner.app/Runner")
            self.assertEqual(executable.create_system, 3)
            self.assertTrue((executable.external_attr >> 16) & stat.S_IXUSR)
            info = plistlib.loads(archive.read("Payload/Runner.app/Info.plist"))
            self.assertEqual(info["CFBundleIdentifier"], "com.sesori.app")
        digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
        self.assertEqual((self.output / "SHA256SUMS").read_text(), f"{digest}  {ipa.name}\n")
        report = json.loads((self.output / "build-info.json").read_text())
        self.assertEqual(report["commit"], COMMIT)
        self.assertEqual(report["runUrl"], RUN_URL)
        self.assertEqual(report["sha256"], digest)
        self.assertEqual(report["signing"], "unsigned")
        self.assertEqual(report["deviceInstallationVerified"], False)
        self.assertEqual(report["minimumOSVersion"], "15.0")
        self.assertEqual({entry["path"] for entry in report["nativeBinaries"]}, {
            "Runner", "Frameworks/App.framework/App", "Frameworks/Flutter.framework/Flutter",
        })

    def test_rejects_simulator_bundle_before_export(self):
        self.info["DTPlatformName"] = "iphonesimulator"
        self.info["CFBundleSupportedPlatforms"] = ["iPhoneSimulator"]
        self.write_plist(self.app / "Info.plist", self.info)
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iPhoneOS device", result.stderr)
        self.assertFalse(self.output.exists())

    def test_excludes_static_link_inputs_without_changing_the_built_app(self):
        framework = self.app / "Frameworks/FirebaseAnalytics.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": "FirebaseAnalytics", "MinimumOSVersion": "100.0",
        })
        static_binary = framework / "FirebaseAnalytics"
        static_binary.write_bytes(b"!<arch>\n" + b"fixture static link input")
        bundle = self.app / "FirebaseAnalyticsResources.bundle"
        bundle.mkdir()
        (bundle / "PrivacyInfo.xcprivacy").write_bytes(b"fixture resource")

        result = self.run_packager()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.output / "build-info.json").read_text())
        self.assertEqual(report["excludedStaticFrameworks"], [
            "Frameworks/FirebaseAnalytics.framework",
        ])
        with zipfile.ZipFile(self.output / report["artifact"]) as archive:
            self.assertFalse(any("FirebaseAnalytics.framework" in name for name in archive.namelist()))
            self.assertEqual(archive.read("Payload/Runner.app/FirebaseAnalyticsResources.bundle/PrivacyInfo.xcprivacy"),
                             b"fixture resource")
            self.assertIn("Payload/Runner.app/Frameworks/Flutter.framework/Flutter", archive.namelist())
        self.assertEqual(static_binary.read_bytes(), b"!<arch>\n" + b"fixture static link input")
        self.assertEqual(plistlib.loads((framework / "Info.plist").read_bytes())["MinimumOSVersion"], "100.0")

    def test_firebase_dynamic_framework_still_must_support_ios15(self):
        framework = self.app / "Frameworks/FirebaseAnalytics.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": "FirebaseAnalytics", "MinimumOSVersion": "100.0",
        })
        self.write_binary(framework / "FirebaseAnalytics")
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iOS 15", result.stderr)
        self.assertFalse(self.output.exists())

    def test_excludes_universal_static_frameworks_without_mutating_the_build(self):
        framework = self.app / "Frameworks/FirebaseAnalytics.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": "FirebaseAnalytics", "MinimumOSVersion": "100.0",
        })
        for wide in (False, True):
            with self.subTest(wide=wide):
                self.output = self.root / f"output-fat-{wide}"
                binary = self.universal_binary(b"!<arch>\nfixture one", b"!<arch>\nfixture two", wide=wide)
                (framework / "FirebaseAnalytics").write_bytes(binary)
                result = self.run_packager()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = json.loads((self.output / "build-info.json").read_text())
                self.assertEqual(report["excludedStaticFrameworks"], ["Frameworks/FirebaseAnalytics.framework"])
                with zipfile.ZipFile(self.output / report["artifact"]) as archive:
                    self.assertFalse(any("FirebaseAnalytics.framework" in name for name in archive.namelist()))
                    self.assertIn("Payload/Runner.app/Frameworks/Flutter.framework/Flutter", archive.namelist())
                self.assertEqual((framework / "FirebaseAnalytics").read_bytes(), binary)
                self.assertEqual(plistlib.loads((framework / "Info.plist").read_bytes())["MinimumOSVersion"], "100.0")

    def test_universal_dynamic_mixed_or_malformed_frameworks_are_not_static_exclusions(self):
        framework = self.app / "Frameworks/FirebaseAnalytics.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": "FirebaseAnalytics", "MinimumOSVersion": "100.0",
        })
        dynamic = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 6, 0, 0, 0, 0)
        static = b"!<arch>\nfixture"
        cases = {
            "dynamic": self.universal_binary(dynamic),
            "mixed": self.universal_binary(static, dynamic),
            "truncated-table": struct.pack(">II", 0xCAFEBABE, 1),
            "out-of-bounds": struct.pack(">7I", 0xCAFEBABE, 1, 0x0100000C, 0, 4096, 64, 12),
            "table-as-slice": struct.pack(">7I", 0xCAFEBABE, 1, 0x0100000C, 0, 8, 8, 0),
            "empty": struct.pack(">II", 0xCAFEBABE, 0),
        }
        for name, binary in cases.items():
            with self.subTest(name=name):
                (framework / "FirebaseAnalytics").write_bytes(binary)
                result = self.run_packager()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("iOS 15", result.stderr)
                self.assertFalse(self.output.exists())

    def test_duplicate_or_overlapping_universal_slices_never_produce_an_ipa(self):
        framework = self.app / "Frameworks/FirebaseAnalytics.framework"
        self.write_plist(framework / "Info.plist", {
            "CFBundleExecutable": "FirebaseAnalytics", "MinimumOSVersion": "100.0",
        })
        for wide in (False, True):
            record_size = 32 if wide else 20
            for defect in ("duplicate-architecture", "overlapping-slices"):
                with self.subTest(wide=wide, defect=defect):
                    self.output = self.root / f"output-{wide}-{defect}"
                    binary = bytearray(self.universal_binary(
                        b"!<arch>\nfixture one", b"!<arch>\nfixture two", wide=wide))
                    second = 8 + record_size
                    if defect == "duplicate-architecture":
                        binary[second:second + 8] = binary[8:16]
                    else:
                        struct.pack_into(">Q" if wide else ">I", binary, second + 8, 4096)
                    (framework / "FirebaseAnalytics").write_bytes(binary)
                    result = self.run_packager()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("iOS 15", result.stderr)
                    self.assertFalse(self.output.exists())

    def test_required_binaries_cannot_be_replaced_by_universal_static_archives(self):
        for relative in ("Runner", "Frameworks/App.framework/App", "Frameworks/Flutter.framework/Flutter"):
            with self.subTest(relative=relative):
                self.output = self.root / ("output-" + relative.replace("/", "-"))
                path = self.app / relative
                original = path.read_bytes()
                path.write_bytes(self.universal_binary(b"!<arch>\nfixture"))
                result = self.run_packager()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("arm64", result.stderr)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_required_flutter_binary_cannot_be_replaced_by_static_link_input(self):
        (self.app / "Frameworks/App.framework/App").write_bytes(b"!<arch>\nfixture")
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("arm64", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_x64_in_embedded_framework_before_export(self):
        self.write_binary(self.app / "Frameworks/App.framework/App", cpu=0x01000007)
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("arm64", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_app_or_framework_that_requires_newer_ios(self):
        for target in (self.app / "Info.plist", self.app / "Frameworks/Flutter.framework/Info.plist"):
            with self.subTest(target=target.name):
                original = target.read_bytes()
                info = plistlib.loads(original)
                info["MinimumOSVersion"] = "16.0"
                self.write_plist(target, info)
                result = self.run_packager()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("iOS 15", result.stderr)
                self.assertFalse(self.output.exists())
                target.write_bytes(original)

    def test_missing_flutter_assets_never_produces_an_ipa(self):
        (self.app / "Frameworks/App.framework/flutter_assets/AssetManifest.bin").unlink()
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Flutter assets", result.stderr)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "keep.txt"
        marker.write_text("user-owned")
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(marker.read_text(), "user-owned")
        self.assertEqual(list(self.output.iterdir()), [marker])


if __name__ == "__main__":
    unittest.main()
