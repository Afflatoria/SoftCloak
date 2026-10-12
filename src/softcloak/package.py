"""Build an aligned APK zip."""

from __future__ import annotations

import struct
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


def _deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


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


def sign_apk(
    unsigned: Path,
    dest: Path,
    *,
    keystore: Path | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    alias: str = "repack",
) -> list[str]:
    """Sign an APK in-process. Imported lazily so zip building does not load crypto."""
    from softcloak.signing import sign_apk as sign_in_process

    return sign_in_process(
        unsigned,
        dest,
        keystore=keystore,
        storepass=storepass,
        keypass=keypass,
        alias=alias,
    )
