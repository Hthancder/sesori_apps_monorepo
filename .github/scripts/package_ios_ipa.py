"""Package a real Flutter device build; never sign, install, or publish it."""

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import struct
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


def is_static_archive(*, path: Path) -> bool:
    """Recognize both plain archives and universal wrappers around archives."""
    with path.open("rb") as stream:
        header = stream.read(8)
        if header == b"!<arch>\n":
            return True
        formats = {b"\xca\xfe\xba\xbe": ">IIIII", b"\xca\xfe\xba\xbf": ">IIQQII"}
        record_format = formats.get(header[:4])
        if record_format is None or len(header) != 8:
            return False
        count = struct.unpack_from(">I", header, 4)[0]
        record_size = struct.calcsize(record_format)
        table_end = 8 + count * record_size
        file_size = os.fstat(stream.fileno()).st_size
        if count == 0 or table_end > file_size:
            return False
        architectures = set()
        ranges = []
        for index in range(count):
            stream.seek(8 + index * record_size)
            record = stream.read(record_size)
            if len(record) != record_size:
                return False
            cpu, subtype, offset, size, *_ = struct.unpack(record_format, record)
            if (cpu, subtype) in architectures:
                return False
            architectures.add((cpu, subtype))
            if offset < table_end or size < 8 or offset + size > file_size:
                return False
            ranges.append((offset, offset + size))
            stream.seek(offset)
            if stream.read(8) != b"!<arch>\n":
                return False
        ranges.sort()
        return all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:]))


def macho_commands(*, path: Path) -> list[tuple[int, int, int, list[bytes]]]:
    """Read bounded 64-bit load commands, including each universal slice."""
    with path.open("rb") as stream:
        header = stream.read(8)
        file_size = os.fstat(stream.fileno()).st_size
        slices = [(0, file_size)]
        formats = {b"\xca\xfe\xba\xbe": ">IIIII", b"\xca\xfe\xba\xbf": ">IIQQII"}
        if header[:4] in formats:
            record_format = formats[header[:4]]
            record_size = struct.calcsize(record_format)
            count = struct.unpack_from(">I", header, 4)[0]
            table_end = 8 + count * record_size
            if count == 0 or table_end > file_size:
                raise ValueError(f"Invalid universal binary: {path}")
            slices = []
            architectures = set()
            for index in range(count):
                stream.seek(8 + index * record_size)
                cpu, subtype, offset, size, *_ = struct.unpack(record_format, stream.read(record_size))
                if ((cpu, subtype) in architectures or offset < table_end or size < 32
                        or offset + size > file_size):
                    raise ValueError(f"Invalid universal slice: {path}")
                architectures.add((cpu, subtype))
                slices.append((offset, size))
            ranges = sorted(slices)
            if any(left[0] + left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
                raise ValueError(f"Overlapping universal slices: {path}")
        result = []
        for offset, size in slices:
            stream.seek(offset)
            header = stream.read(32)
            if len(header) != 32 or header[:4] != b"\xcf\xfa\xed\xfe":
                raise ValueError(f"Expected 64-bit Mach-O load commands: {path}")
            _, cpu, _, filetype, count, length, _, _ = struct.unpack("<8I", header)
            if length > size - 32 or count > length // 8:
                raise ValueError(f"Invalid Mach-O load command bounds: {path}")
            table = stream.read(length)
            commands = []
            position = 0
            for _ in range(count):
                if position + 8 > len(table):
                    raise ValueError(f"Truncated Mach-O load command: {path}")
                _, command_size = struct.unpack_from("<II", table, position)
                if command_size < 8 or command_size % 8 or position + command_size > len(table):
                    raise ValueError(f"Invalid Mach-O load command size: {path}")
                commands.append(table[position:position + command_size])
                position += command_size
            if position != length:
                raise ValueError(f"Unexpected Mach-O load command bytes: {path}")
            result.append((offset, cpu, filetype, commands))
        return result


def dylib_name(*, command: bytes) -> str:
    if len(command) < 24:
        raise ValueError("Truncated Mach-O dylib command")
    offset = struct.unpack_from("<I", command, 8)[0]
    if not 24 <= offset < len(command) or b"\0" not in command[offset:]:
        raise ValueError("Invalid Mach-O dylib name")
    return command[offset:].split(b"\0", 1)[0].decode("utf-8")


def is_empty_analytics_stub(*, path: Path, name: str) -> bool:
    # These exact four built products were inspected in Actions run 45762104177.
    # Xcode emitted empty dylibs for link-time analytics inputs, with minos 100.
    if name not in {"FirebaseAnalytics", "GoogleAdsOnDeviceConversion",
                    "GoogleAppMeasurement", "GoogleAppMeasurementIdentitySupport"}:
        return False
    try:
        slices = macho_commands(path=path)
        if len(slices) != 1:
            return False
        base, cpu, filetype, commands = slices[0]
        if cpu != 0x0100000C or filetype != 6:
            return False
        found = set()
        allowed = {0x19, 0xD, 0x80000034, 0x80000033, 2, 0xB, 0x1B,
                   0x32, 0x2A, 0x2C, 0xC, 0x26, 0x29, 0x1D}
        for command in commands:
            kind = struct.unpack_from("<I", command)[0]
            if kind not in allowed:
                return False
            if kind == 0x19:
                if len(command) < 72 or command[8:24].rstrip(b"\0") not in (b"__TEXT", b"__LINKEDIT"):
                    return False
                count = struct.unpack_from("<I", command, 64)[0]
                if len(command) != 72 + count * 80:
                    return False
                for index in range(count):
                    section = command[72 + index * 80:152 + index * 80]
                    if section[:16].rstrip(b"\0") != b"__text" or struct.unpack_from("<Q", section, 40)[0] != 0:
                        return False
                    found.add("empty-text")
            elif kind in (0xC, 0xD):
                expected = "/usr/lib/libSystem.B.dylib" if kind == 0xC else f"@rpath/{name}.framework/{name}"
                if dylib_name(command=command) != expected:
                    return False
                found.add(kind)
            elif kind == 2:
                if len(command) != 24 or struct.unpack_from("<I", command, 12)[0] != 0:
                    return False
                found.add(kind)
            elif kind == 0x80000033:
                if len(command) != 16:
                    return False
                offset, length = struct.unpack_from("<II", command, 8)
                with path.open("rb") as stream:
                    stream.seek(base + offset)
                    if length != 8 or stream.read(length) != bytes(8):
                        return False
                found.add(kind)
            elif kind == 0x32:
                if len(command) < 24 or struct.unpack_from("<II", command, 8) != (2, 100 << 16):
                    return False
                found.add(kind)
        return found == {"empty-text", 0xC, 0xD, 2, 0x80000033, 0x32}
    except (ValueError, struct.error):
        return False


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
    excluded_static_frameworks = []
    excluded_empty_stubs = []
    for plist in sorted((app / "Frameworks").glob("*.framework/Info.plist")):
        framework_info = read_info(path=plist)
        framework_executable = framework_info.get("CFBundleExecutable")
        if isinstance(framework_executable, str) and Path(framework_executable).name == framework_executable:
            binary = plist.parent / framework_executable
            if binary.is_file() and binary.relative_to(app).as_posix() not in required:
                if is_static_archive(path=binary):
                    # Static link inputs are already linked into the app, not runtime frameworks.
                    # Apple TN2435: static frameworks must not be embedded in an iOS app.
                    excluded_static_frameworks.append(plist.parent)
                    continue
                if (framework_info.get("MinimumOSVersion") == "100.0"
                        and is_empty_analytics_stub(path=binary, name=framework_executable)):
                    excluded_empty_stubs.append(plist.parent)
                    continue
        # Some third-party frameworks omit this key; the app and Flutter engine do not.
        if "MinimumOSVersion" in framework_info:
            check_minimum_ios(info=framework_info, path=plist)

    binaries = []
    files = [path for path in sorted(app.rglob("*"))
             if not any(path.is_relative_to(framework)
                        for framework in excluded_static_frameworks + excluded_empty_stubs)]
    for path in files:
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(app).as_posix()
        if relative in required and is_static_archive(path=path):
            raise ValueError(f"Expected arm64 Mach-O binary, not a static archive: {relative}")
        native = native_arch(path=path)
        if native is None:
            if relative in required or path.suffix == ".dylib":
                raise ValueError(f"Expected arm64 Mach-O binary: {relative}")
            continue
        binary_format, arches = native
        if binary_format != "Mach-O" or "arm64" not in arches:
            raise ValueError(f"Expected arm64 Mach-O binary: {relative}: {native}")
        if excluded_empty_stubs:
            for _, _, _, commands in macho_commands(path=path):
                for command in commands:
                    if struct.unpack_from("<I", command)[0] not in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
                        continue
                    dependency = dylib_name(command=command)
                    for framework in excluded_empty_stubs:
                        if dependency.endswith(f"/{framework.name}/{framework.stem}"):
                            raise ValueError(f"Referenced framework requires iOS 100, not iOS 15: {dependency} from {relative}")
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
        "excludedStaticFrameworks": [path.relative_to(app).as_posix() for path in excluded_static_frameworks],
        "excludedEmptyStubFrameworks": [path.relative_to(app).as_posix() for path in excluded_empty_stubs],
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
