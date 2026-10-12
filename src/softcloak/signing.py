"""Sign an APK with a JAR v1 signature and an APK v2 signing block."""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import struct
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options
from cryptography.x509.oid import NameOID

from softcloak.package import SIGNING_BLOCK_MAGIC, build_zip, is_signature_entry

CHUNK_SIZE = 1024 * 1024
V2_BLOCK_ID = 0x7109871A
V2_RSA_SHA256 = 0x0103
_CREATED_BY = "SoftCloak"


def generate_signing_identity() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Create a self-signed RSA certificate, the same role keytool played."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Local"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SoftCloak"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=10000))
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def load_signing_identity(
    keystore: Path,
    storepass: str,
    alias: str,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Load an RSA key and certificate from a PKCS12 keystore."""
    data = Path(keystore).read_bytes()
    if data.startswith(b"\xfe\xed\xfe\xed"):
        raise ValueError(
            "Java JKS keystores cannot be read without a JDK. "
            "Export a PKCS12 .p12 file and pass that as --keystore."
        )
    try:
        loaded = pkcs12.load_pkcs12(data, storepass.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("could not read the PKCS12 keystore") from exc
    if loaded.key is None or loaded.cert is None:
        raise ValueError("the PKCS12 keystore has no private key and certificate")
    friendly = loaded.cert.friendly_name
    if isinstance(friendly, bytes):
        friendly = friendly.decode("utf-8", "replace")
    if friendly and friendly != alias:
        raise ValueError(
            f"keystore alias is {friendly!r}, not {alias!r}. Pass --alias {friendly}."
        )
    key = loaded.key
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("the keystore key must be RSA")
    return key, loaded.cert.certificate


def sign_apk(
    unsigned: Path,
    dest: Path,
    *,
    keystore: Path | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    alias: str = "repack",
) -> list[str]:
    """Sign ``unsigned`` and write a v1 and v2 signed APK to ``dest``."""
    del keypass  # PKCS12 uses the store password for the key as well.
    if keystore is None:
        private_key, certificate = generate_signing_identity()
    else:
        if storepass is None:
            raise RuntimeError("storepass is required when keystore is provided")
        private_key, certificate = load_signing_identity(keystore, storepass, alias)

    with zipfile.ZipFile(unsigned) as archive:
        content = [
            (info, archive.read(info.filename))
            for info in archive.infolist()
            if not is_signature_entry(info.filename)
        ]
    signature_files = _jar_signature_files(content, private_key, certificate, alias)
    dest.parent.mkdir(parents=True, exist_ok=True)
    build_zip([*signature_files, *content], dest)
    dest.write_bytes(_attach_v2_signature(dest.read_bytes(), private_key, certificate))
    verify_apk(dest.read_bytes())
    return []


def verify_apk(apk: bytes) -> None:
    """Check the JAR digests and the v2 signature. Raise if either is wrong."""
    _verify_jar(apk)
    _verify_v2(apk)


def _jar_signature_files(
    entries: list[tuple[zipfile.ZipInfo, bytes]],
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
    alias: str,
) -> list[tuple[zipfile.ZipInfo, bytes]]:
    manifest, sections = _manifest(entries)
    signature_file = _signature_file(manifest, sections)
    block = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(signature_file)
        .add_signer(certificate, private_key, hashes.SHA256())
        .add_certificate(certificate)
        .sign(
            serialization.Encoding.DER,
            [PKCS7Options.DetachedSignature, PKCS7Options.Binary],
        )
    )
    stem = _signature_stem(alias)
    return [
        (_stored(f"META-INF/{name}"), payload)
        for name, payload in (
            ("MANIFEST.MF", manifest),
            (f"{stem}.SF", signature_file),
            (f"{stem}.RSA", block),
        )
    ]


def _manifest(
    entries: list[tuple[zipfile.ZipInfo, bytes]],
) -> tuple[bytes, list[tuple[str, bytes]]]:
    main = _lines(
        [
            "Manifest-Version: 1.0",
            f"Created-By: {_CREATED_BY}",
        ]
    )
    sections: list[tuple[str, bytes]] = []
    body = bytearray(main)
    for info, data in entries:
        digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        section = _lines(
            [
                f"Name: {info.filename}",
                f"SHA-256-Digest: {digest}",
            ]
        )
        sections.append((info.filename, section))
        body += section
    return bytes(body), sections


def _signature_file(manifest: bytes, sections: list[tuple[str, bytes]]) -> bytes:
    main_end = manifest.index(b"\r\n\r\n") + 4
    main_digest = base64.b64encode(hashlib.sha256(manifest[:main_end]).digest()).decode(
        "ascii"
    )
    manifest_digest = base64.b64encode(hashlib.sha256(manifest).digest()).decode(
        "ascii"
    )
    parts = [
        _lines(
            [
                "Signature-Version: 1.0",
                f"Created-By: {_CREATED_BY}",
                "X-Android-APK-Signed: 2",
                f"SHA-256-Digest-Manifest: {manifest_digest}",
                f"SHA-256-Digest-Manifest-Main-Attributes: {main_digest}",
            ]
        )
    ]
    for name, section in sections:
        digest = base64.b64encode(hashlib.sha256(section).digest()).decode("ascii")
        parts.append(_lines([f"Name: {name}", f"SHA-256-Digest: {digest}"]))
    return b"".join(parts)


def _lines(rows: list[str]) -> bytes:
    wrapped: list[bytes] = []
    for row in rows:
        raw = row.encode("utf-8")
        first, raw = raw[:72], raw[72:]
        wrapped.append(first)
        while raw:
            nxt, raw = raw[:71], raw[71:]
            wrapped.append(b" " + nxt)
    return b"\r\n".join(wrapped) + b"\r\n\r\n"


def _signature_stem(alias: str) -> str:
    if not alias or any(char in alias for char in '\\/:*?"<>|'):
        raise ValueError(f"alias cannot be used as a signature file name: {alias!r}")
    return alias.upper()


def _stored(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_STORED
    info.date_time = (2026, 10, 12, 0, 0, 0)
    return info


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _length_prefixed(payload: bytes) -> bytes:
    return _u32(len(payload)) + payload


def _sequence(items: list[bytes]) -> bytes:
    payload = b"".join(_length_prefixed(item) for item in items)
    return _u32(len(payload)) + payload


def _content_digest(sections: list[bytes]) -> bytes:
    chunk_digests: list[bytes] = []
    for section in sections:
        offset = 0
        while offset < len(section):
            size = min(CHUNK_SIZE, len(section) - offset)
            chunk = section[offset : offset + size]
            prefixed = b"\xa5" + _u32(size) + chunk
            chunk_digests.append(hashlib.sha256(prefixed).digest())
            offset += size
    payload = b"\x5a" + _u32(len(chunk_digests)) + b"".join(chunk_digests)
    return hashlib.sha256(payload).digest()


def _v2_signer(
    digest: bytes,
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
) -> tuple[bytes, bytes]:
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    digest_record = _u32(V2_RSA_SHA256) + _length_prefixed(digest)
    signed_data = (
        _sequence([digest_record]) + _sequence([certificate_der]) + _sequence([])
    )
    signature = private_key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    signature_record = _u32(V2_RSA_SHA256) + _length_prefixed(signature)
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signer = (
        _length_prefixed(signed_data)
        + _sequence([signature_record])
        + _length_prefixed(public_key)
    )
    return _sequence([signer]), signed_data


def _signing_block(pairs: list[tuple[int, bytes]]) -> bytes:
    encoded = b"".join(
        _u64(4 + len(value)) + _u32(block_id) + value for block_id, value in pairs
    )
    size = len(encoded) + 8 + len(SIGNING_BLOCK_MAGIC)
    return _u64(size) + encoded + _u64(size) + SIGNING_BLOCK_MAGIC


def _eocd_offset(apk: bytes) -> int:
    start = max(0, len(apk) - (65535 + 22))
    position = apk.rfind(b"PK\x05\x06", start)
    if position < 0:
        raise RuntimeError("APK is missing the ZIP end of central directory")
    return position


def _attach_v2_signature(
    apk: bytes,
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
) -> bytes:
    eocd_at = _eocd_offset(apk)
    central_offset = struct.unpack_from("<I", apk, eocd_at + 16)[0]
    central_size = struct.unpack_from("<I", apk, eocd_at + 12)[0]
    before = apk[:central_offset]
    central = apk[central_offset : central_offset + central_size]
    eocd = bytearray(apk[eocd_at:])
    digest = _content_digest([before, central, bytes(eocd)])
    signers, _signed_data = _v2_signer(digest, private_key, certificate)
    block = _signing_block([(V2_BLOCK_ID, signers)])
    struct.pack_into("<I", eocd, 16, central_offset + len(block))
    return before + block + central + bytes(eocd)


def _verify_jar(apk: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        manifest = archive.read("META-INF/MANIFEST.MF")
        for info in archive.infolist():
            if is_signature_entry(info.filename) or info.filename.endswith("/"):
                continue
            digest = base64.b64encode(
                hashlib.sha256(archive.read(info.filename)).digest()
            )
            if digest not in manifest:
                raise RuntimeError(f"JAR manifest has no digest for {info.filename}")


def _verify_v2(apk: bytes) -> None:
    eocd_at = _eocd_offset(apk)
    central_offset = struct.unpack_from("<I", apk, eocd_at + 16)[0]
    central_size = struct.unpack_from("<I", apk, eocd_at + 12)[0]
    magic_at = central_offset - len(SIGNING_BLOCK_MAGIC)
    if apk[magic_at:central_offset] != SIGNING_BLOCK_MAGIC:
        raise RuntimeError("APK is missing a v2 signing block")
    block_size = struct.unpack_from("<Q", apk, magic_at - 8)[0]
    block_start = central_offset - (block_size + 8)
    before = apk[:block_start]
    central = apk[central_offset : central_offset + central_size]
    eocd = bytearray(apk[eocd_at:])
    struct.pack_into("<I", eocd, 16, block_start)
    expected = _content_digest([before, central, bytes(eocd)])
    pairs = apk[block_start + 8 : magic_at - 8]
    value = _pair_value(pairs, V2_BLOCK_ID)
    signed_data, digest, signature, certificate = _parse_v2_signer(value)
    if digest != expected:
        raise RuntimeError("v2 content digest does not match the APK")
    certificate.public_key().verify(
        signature, signed_data, padding.PKCS1v15(), hashes.SHA256()
    )


def _pair_value(pairs: bytes, wanted: int) -> bytes:
    offset = 0
    while offset + 12 <= len(pairs):
        size = struct.unpack_from("<Q", pairs, offset)[0]
        block_id = struct.unpack_from("<I", pairs, offset + 8)[0]
        value = pairs[offset + 12 : offset + 8 + size]
        if block_id == wanted:
            return value
        offset += 8 + size
    raise RuntimeError("v2 signature block was not found")


def _take(blob: bytes, offset: int) -> tuple[bytes, int]:
    size = struct.unpack_from("<I", blob, offset)[0]
    start = offset + 4
    return blob[start : start + size], start + size


def _parse_v2_signer(
    signers_blob: bytes,
) -> tuple[bytes, bytes, bytes, x509.Certificate]:
    signers, _end = _take(signers_blob, 0)
    signer, _next = _take(signers, 0)
    signed_data, cursor = _take(signer, 0)
    digests, after_digests = _take(signed_data, 0)
    digest_record, _cursor = _take(digests, 0)
    digest, _cursor = _take(digest_record, 4)
    signatures, _cursor = _take(signer, cursor)
    signature_record, _cursor = _take(signatures, 0)
    signature, _cursor = _take(signature_record, 4)
    certificates, _cursor = _take(signed_data, after_digests)
    certificate_der, _cursor = _take(certificates, 0)
    certificate = x509.load_der_x509_certificate(certificate_der)
    return signed_data, digest, signature, certificate
