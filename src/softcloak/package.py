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


def is_signature_entry(name: str) -> bool:
    if not name.upper().startswith("META-INF/"):
        return False
    base = name.rsplit("/", 1)[-1].upper()
    return base == "MANIFEST.MF" or base.startswith("SIG-") or base.endswith(SIGNATURE_SUFFIXES)


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


def build_zip(entries: list[tuple[zipfile.ZipInfo, bytes]], dest: Path) -> None:
    blob = bytearray()
    central = bytearray()
    for info, data in entries:
        name_b = info.filename.encode("utf-8")
        method = zipfile.ZIP_STORED if info.compress_type == zipfile.ZIP_STORED else zipfile.ZIP_DEFLATED
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if method == zipfile.ZIP_STORED:
            payload = data
            pad = (4 - ((len(blob) + 30 + len(name_b)) % 4)) % 4
            extra = b"\x00" * pad
        else:
            payload = _deflate(data)
            extra = b""
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
        if method == zipfile.ZIP_STORED and (local_off + 30 + len(name_b) + len(extra)) % 4 != 0:
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
    result = subprocess.run(command, capture_output=True, text=True)
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
) -> None:
    keytool = find_java_tool("keytool")
    jarsigner = find_java_tool("jarsigner")
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
                (info, archive.read(info.filename))
                for info in archive.infolist()
            ]
        build_zip(entries, dest)
        result = subprocess.run(
            [jarsigner, "-verify", str(dest)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(f"signed APK failed verification: {detail}")
