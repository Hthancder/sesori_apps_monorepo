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

    def run_packager(self):
        return subprocess.run([
            sys.executable, str(SCRIPT), "--app", str(self.app),
            "--output", str(self.output), "--commit", COMMIT, "--run-url", RUN_URL,
        ], capture_output=True, text=True)

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
