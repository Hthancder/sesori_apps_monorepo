"""Package a real Flutter device build; never sign, install, or publish it."""

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import zipfile
from pathlib import Path

from qualify_desktop import native_arch


def read_info(*, path: Path) -> dict:
    with path.open("rb") as stream:
        return plistlib.load(stream)


def check_minimum_ios(*, info: dict, path: Path) -> None:
    version = info.get("MinimumOSVersion")
    if not isinstance(version, str) or not re.fullmatch(r"\d+(?:\.\d+){0,2}", version):
        raise ValueError(f"Missing or invalid MinimumOSVersion: {path}")
    parts = tuple(int(part) for part in version.split("."))
    if (parts + (0,) * (3 - len(parts))) > (15, 0, 0):
        raise ValueError(f"Bundle requires {version}, not iOS 15: {path}")


def package(*, app: Path, output: Path, commit: str, run_url: str) -> dict:
    app = app.resolve()
    output = output.resolve()
    if output.exists():
        raise ValueError(f"Output already exists; refusing to overwrite: {output}")
    if output.is_relative_to(app):
        raise ValueError("Output must be outside the app bundle")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected a full Git commit SHA")
    if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/actions/runs/\d+", run_url):
        raise ValueError("Expected a GitHub Actions run URL")

    info = read_info(path=app / "Info.plist")
    if info.get("DTPlatformName") != "iphoneos" or info.get("CFBundleSupportedPlatforms") != ["iPhoneOS"]:
        raise ValueError("Expected an iPhoneOS device build, not a simulator bundle")
    check_minimum_ios(info=info, path=app / "Info.plist")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or Path(executable).name != executable:
        raise ValueError("Invalid CFBundleExecutable")
    version = info.get("CFBundleShortVersionString")
    build = info.get("CFBundleVersion")
    if any(not isinstance(value, str) or not re.fullmatch(r"\d+(?:\.\d+)*", value)
           for value in (version, build)):
        raise ValueError("Invalid bundle version or build number")
    required = {executable, "Frameworks/App.framework/App", "Frameworks/Flutter.framework/Flutter"}
    for relative in required:
        if not (app / relative).is_file():
            raise ValueError(f"Missing required Flutter binary: {relative}")
    assets = app / "Frameworks/App.framework/flutter_assets"
    if not assets.is_dir() or not any(path.is_file() for path in assets.rglob("*")):
        raise ValueError("Missing Flutter assets")
    for plist in sorted((app / "Frameworks").glob("*.framework/Info.plist")):
        framework_info = read_info(path=plist)
        # Some third-party frameworks omit this key; the app and Flutter engine do not.
        if "MinimumOSVersion" in framework_info:
            check_minimum_ios(info=framework_info, path=plist)

    binaries = []
    files = sorted(app.rglob("*"))
    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(app).as_posix()
        native = native_arch(path=path)
        if native is None:
            if relative in required or path.suffix == ".dylib":
                raise ValueError(f"Expected arm64 Mach-O binary: {relative}")
            continue
        binary_format, arches = native
        if binary_format != "Mach-O" or "arm64" not in arches:
            raise ValueError(f"Expected arm64 Mach-O binary: {relative}: {native}")
        binaries.append({"path": relative, "architectures": arches})
    native_paths = {entry["path"] for entry in binaries}
    if not required.issubset(native_paths):
        raise ValueError("Missing required arm64 binaries")

    output.mkdir(parents=True)
    ipa = output / f"Sesori-ios-{version}-{build}-unsigned.ipa"
    with zipfile.ZipFile(ipa, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(app).as_posix()
            name = f"Payload/{app.name}/{relative}"
            entry = zipfile.ZipInfo.from_file(path, arcname=name)
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_DEFLATED
            mode = path.lstat().st_mode
            if relative in native_paths:
                mode |= 0o111
            entry.external_attr = mode << 16
            if path.is_symlink():
                archive.writestr(entry, os.readlink(path).encode())
            elif path.is_dir():
                archive.writestr(entry, b"")
            else:
                with path.open("rb") as source, archive.open(entry, "w") as target:
                    shutil.copyfileobj(source, target)
    with zipfile.ZipFile(ipa) as archive:
        if archive.testzip() is not None:
            raise ValueError("IPA failed ZIP integrity check")
    with ipa.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {
        "artifact": ipa.name, "sha256": digest, "bytes": ipa.stat().st_size,
        "commit": commit, "runUrl": run_url, "bundleIdentifier": info["CFBundleIdentifier"],
        "version": version, "build": build, "minimumOSVersion": info["MinimumOSVersion"],
        "signing": "unsigned", "deviceInstallationVerified": False, "nativeBinaries": binaries,
    }
    (output / "SHA256SUMS").write_text(f"{digest}  {ipa.name}\n", encoding="utf-8")
    (output / "build-info.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()
    try:
        report = package(app=args.app, output=args.output, commit=args.commit, run_url=args.run_url)
    except (ValueError, OSError, plistlib.InvalidFileException) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
