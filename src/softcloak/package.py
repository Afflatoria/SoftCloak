"""Build an aligned APK and sign it with jarsigner."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path

SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")
STORED_ALIGNMENT = 4
# Stored native libraries are mapped from the APK. 16384 satisfies 4 KB and 16 KB pages.
PAGE_ALIGNMENT = 16384
SIGNING_BLOCK_MAGIC = b"APK Sig Block 42"


def is_signature_entry(name: str) -> bool:
    if not name.upper().startswith("META-INF/"):
        return False
    base = name.rsplit("/", 1)[-1].upper()
    return (
        base == "MANIFEST.MF"
        or base.startswith("SIG-")
        or base.endswith(SIGNATURE_SUFFIXES)
    )


def find_java_tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        suffix = ".exe" if os.name == "nt" else ""
        candidate = Path(java_home) / "bin" / f"{name}{suffix}"
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError(f"Could not find {name}. Install a JDK and put it on PATH.")


def _deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _version_numbers(name: str) -> tuple[int, ...]:
    numbers = []
    for piece in name.split("."):
        digits = ""
        for char in piece:
            if not char.isdigit():
                break
            digits += char
        numbers.append(int(digits) if digits else -1)
    return tuple(numbers)


def _entry_alignment(filename: str, method: int) -> int:
    if method != zipfile.ZIP_STORED:
        return 1
    if filename.lower().endswith(".so"):
        return PAGE_ALIGNMENT
    return STORED_ALIGNMENT


def _alignment_extra(offset: int, name_len: int, alignment: int) -> bytes:
    if alignment <= 1:
        return b""
    start = offset + 30 + name_len
    pad = (alignment - (start % alignment)) % alignment
    return b"\x00" * pad


def find_apksigner_jar() -> str | None:
    """Return the apksigner jar from APKSIGNER_JAR or an installed Android SDK."""
    override = os.environ.get("APKSIGNER_JAR")
    if override:
        if Path(override).is_file():
            return override
        raise RuntimeError(f"APKSIGNER_JAR does not exist: {override}")
    jars: list[Path] = []
    for root_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(root_name)
        if not root:
            continue
        tools = Path(root) / "build-tools"
        if tools.is_dir():
            jars.extend(tools.glob("*/lib/apksigner.jar"))
    if not jars:
        return None
    newest = max(jars, key=lambda path: _version_numbers(path.parent.parent.name))
    return str(newest)


def build_zip(entries: list[tuple[zipfile.ZipInfo, bytes]], dest: Path) -> None:
    blob = bytearray()
    central = bytearray()
    for info, data in entries:
        name_b = info.filename.encode("utf-8")
        method = (
            zipfile.ZIP_STORED
            if info.compress_type == zipfile.ZIP_STORED
            else zipfile.ZIP_DEFLATED
        )
        crc = zlib.crc32(data) & 0xFFFFFFFF
        alignment = _entry_alignment(info.filename, method)
        extra = _alignment_extra(len(blob), len(name_b), alignment)
        payload = data if method == zipfile.ZIP_STORED else _deflate(data)
        date_time = info.date_time or (2026, 10, 12, 0, 0, 0)
        dos_time = (date_time[3] << 11) | (date_time[4] << 5) | (date_time[5] // 2)
        dos_date = ((date_time[0] - 1980) << 9) | (date_time[1] << 5) | date_time[2]
        local_off = len(blob)
        blob += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            method,
            dos_time,
            dos_date,
            crc,
            len(payload),
            len(data),
            len(name_b),
            len(extra),
        )
        blob += name_b + extra + payload
        data_off = local_off + 30 + len(name_b) + len(extra)
        if alignment > 1 and data_off % alignment != 0:
            raise RuntimeError(f"failed to align {info.filename}")
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            method,
            dos_time,
            dos_date,
            crc,
            len(payload),
            len(data),
            len(name_b),
            len(extra),
            0,
            0,
            0,
            0,
            local_off,
        )
        central += name_b + extra
    cd_off = len(blob)
    blob += central
    blob += struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(central),
        cd_off,
        0,
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(blob)


def _run(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"{command[0]} failed: {detail}")


def sign_apk(
    unsigned: Path,
    dest: Path,
    *,
    keystore: Path | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    alias: str = "repack",
) -> list[str]:
    keytool = find_java_tool("keytool")
    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)
        owned_keystore = keystore is None
        if owned_keystore:
            keystore = temp / "repack.keystore"
            storepass = "android"
            keypass = "android"
            _run(
                [
                    keytool,
                    "-genkeypair",
                    "-keystore",
                    str(keystore),
                    "-storepass",
                    storepass,
                    "-keypass",
                    keypass,
                    "-alias",
                    alias,
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-validity",
                    "10000",
                    "-dname",
                    "CN=SoftCloak, OU=Local, O=Local, C=US",
                ]
            )
        if storepass is None:
            raise RuntimeError("storepass is required when keystore is provided")
        keypass = keypass or storepass
        dest.parent.mkdir(parents=True, exist_ok=True)
        apksigner_jar = find_apksigner_jar()
        if apksigner_jar:
            java = find_java_tool("java")
            _run(
                [
                    java,
                    "-jar",
                    apksigner_jar,
                    "sign",
                    "--ks",
                    str(keystore),
                    "--ks-key-alias",
                    alias,
                    "--ks-pass",
                    f"pass:{storepass}",
                    "--key-pass",
                    f"pass:{keypass}",
                    "--v1-signing-enabled",
                    "true",
                    "--v2-signing-enabled",
                    "true",
                    "--v3-signing-enabled",
                    "true",
                    "--v4-signing-enabled",
                    "false",
                    "--out",
                    str(dest),
                    str(unsigned),
                ]
            )
            _run([java, "-jar", apksigner_jar, "verify", str(dest)])
            if SIGNING_BLOCK_MAGIC not in dest.read_bytes():
                raise RuntimeError("apksigner did not write a v2 signing block")
            return []
        jarsigner = find_java_tool("jarsigner")
        signed = temp / "signed.apk"
        _run(
            [
                jarsigner,
                "-sigalg",
                "SHA256withRSA",
                "-digestalg",
                "SHA-256",
                "-keystore",
                str(keystore),
                "-storepass",
                storepass,
                "-keypass",
                keypass,
                "-signedjar",
                str(signed),
                str(unsigned),
                alias,
            ]
        )
        with zipfile.ZipFile(signed) as archive:
            entries = [
                (info, archive.read(info.filename)) for info in archive.infolist()
            ]
        build_zip(entries, dest)
        result = subprocess.run(
            [jarsigner, "-verify", str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"signed APK failed verification: {detail}")
        return [
            (
                "JAR v1 signature only. apksigner was not found, so v2 and v3 "
                "signatures were not added. An app with targetSdk 30 or higher "
                "will not install on Android 11 or later. Set ANDROID_HOME to an "
                "SDK that includes build-tools."
            )
        ]
