"""In-place APK string replacement that keeps binary lengths stable."""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from softcloak.package import build_zip, is_signature_entry, sign_apk

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".so",
    ".mp3",
    ".ogg",
    ".wav",
    ".ttf",
    ".otf",
}


@dataclass
class Rule:
    kind: str
    old: str
    new: str
    forms: tuple[str, ...] = ()
    replacements: tuple[str, ...] = ()


@dataclass
class RewriteResult:
    output: Path | None
    rules: list[Rule]
    counts: dict[str, tuple[int, int]]
    warnings: list[str] = field(default_factory=list)
    dry_run: bool = False


def _ascii(value: str, label: str) -> None:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"{label} must be ASCII so the APK layout stays intact: {value!r}"
        ) from exc


def _fit(old: str, new: str, mode: str, pad_char: str) -> str:
    if len(pad_char) != 1 or not pad_char.isascii():
        raise ValueError("pad character must be one ASCII character")
    if len(new) == len(old):
        return new
    if mode == "error":
        raise ValueError(
            f"length mismatch for {old!r}: the existing text is {len(old)} characters "
            f"and the replacement is {len(new)}. Use a string of length {len(old)}, "
            "or pass --fit pad or --fit clip."
        )
    if mode == "pad":
        if len(new) > len(old):
            raise ValueError(
                f"replacement for {old!r} is {len(new)} characters and the existing text "
                f"is {len(old)}. --fit pad only fills a shorter string."
            )
        return new + pad_char * (len(old) - len(new))
    if mode == "clip":
        clipped = new[: len(old)]
        return clipped + pad_char * (len(old) - len(clipped))
    raise ValueError(f"unknown fit mode: {mode}")


def obfuscated_token(text: str, blocked: list[str], seed: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    blocked_lower = [item.lower() for item in blocked if item]
    counter = 0
    while counter < 1000:
        material = hashlib.sha256(f"{seed}:{counter}:{text}".encode()).digest()
        chars: list[str] = []
        while len(chars) < len(text):
            material = hashlib.sha256(material).digest()
            chars.extend(alphabet[byte % 26] for byte in material)
        token = "".join(chars[: len(text)])
        haystack = token.lower()
        if token != text and all(item not in haystack for item in blocked_lower):
            return token
        counter += 1
    raise RuntimeError(f"could not build an obfuscated replacement for {text!r}")


def _replace_span(data: bytes, old: bytes, new: bytes) -> tuple[bytes, int]:
    if len(old) != len(new):
        raise ValueError("internal replacement lengths differ")
    count = data.count(old)
    if count:
        data = data.replace(old, new)
    return data, count


def _replacements(rule: Rule) -> tuple[str, ...]:
    if rule.replacements:
        return rule.replacements
    return tuple(rule.new for _form in rule.forms)


def apply_rules(
    data: bytes, rules: list[Rule]
) -> tuple[bytes, dict[str, tuple[int, int]]]:
    counts = {rule.old: [0, 0] for rule in rules}
    for rule in rules:
        for form, replacement in zip(rule.forms, _replacements(rule), strict=True):
            data, utf8_count = _replace_span(
                data, form.encode("utf-8"), replacement.encode("utf-8")
            )
            data, utf16_count = _replace_span(
                data,
                form.encode("utf-16le"),
                replacement.encode("utf-16le"),
            )
            counts[rule.old][0] += utf8_count
            counts[rule.old][1] += utf16_count
    return data, {key: (value[0], value[1]) for key, value in counts.items()}


def separator_forms(text: str) -> tuple[str, ...]:
    """Android class names use '/' in DEX and '.' everywhere else."""
    return tuple(dict.fromkeys((text, text.replace(".", "/"), text.replace("/", "."))))


def separator_pairs(old: str, new: str) -> tuple[tuple[str, str], ...]:
    """Pair each separator spelling of ``old`` with the same spelling of ``new``."""
    candidates = (
        (old, new),
        (old.replace(".", "/"), new.replace(".", "/")),
        (old.replace("/", "."), new.replace("/", ".")),
    )
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for left, right in candidates:
        if left in seen:
            continue
        seen.add(left)
        pairs.append((left, right))
    return tuple(pairs)


def avoid_token_collisions(rules: list[Rule], blobs: list[bytes], seed: str) -> None:
    """Pick another token when a generated replacement is already in the APK."""
    blocked = [item for rule in rules for item in (rule.old, rule.new)]
    for rule in rules:
        if rule.kind != "contains":
            continue
        extra: list[str] = []
        for _attempt in range(50):
            utf8 = rule.new.encode("utf-8")
            utf16 = rule.new.encode("utf-16le")
            if all(utf8 not in blob and utf16 not in blob for blob in blobs):
                blocked.append(rule.new)
                break
            extra.append(rule.new)
            rule.new = obfuscated_token(rule.old, blocked + extra, seed)
            rule.replacements = tuple(rule.new for _form in rule.forms)
        else:
            raise RuntimeError(f"could not find an unused replacement for {rule.old!r}")


def present_in(data: bytes, text: str) -> bool:
    return text.encode("utf-8") in data or text.encode("utf-16le") in data


def rule_present(data: bytes, rule: Rule) -> bool:
    return any(present_in(data, form) for form in rule.forms)


def fix_dex(data: bytes) -> bytes:
    if not data.startswith(b"dex\n"):
        return data
    raw = bytearray(data)
    raw[12:32] = hashlib.sha1(raw[32:]).digest()
    raw[8:12] = struct.pack("<I", zlib.adler32(bytes(raw[12:])) & 0xFFFFFFFF)
    return bytes(raw)


def _skipped(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in SKIP_SUFFIXES)


def build_rules(
    contains: list[str] | None,
    exact: list[tuple[str, str]] | None,
    *,
    seed: str,
    fit: str,
    pad_char: str,
) -> list[Rule]:
    contains = list(contains or [])
    exact = list(exact or [])
    if not contains and not exact:
        raise ValueError(
            "provide at least one --contains substring or --exact replacement"
        )
    for text in contains:
        if not text:
            raise ValueError("--contains does not accept an empty string")
        _ascii(text, "--contains")
    seen = set()
    for text in contains:
        if text in seen:
            raise ValueError(f"repeated --contains value: {text!r}")
        seen.add(text)

    exact_rules: list[Rule] = []
    used_exact: set[str] = set()
    for old, new in exact:
        if not old:
            raise ValueError("--exact does not accept an empty search string")
        _ascii(old, "exact search text")
        _ascii(new, "exact replacement")
        if old in used_exact:
            raise ValueError(f"repeated --exact search string: {old!r}")
        used_exact.add(old)
        fitted = _fit(old, new, fit, pad_char)
        pairs = separator_pairs(old, fitted)
        for text in contains:
            if any(text in replacement for _form, replacement in pairs):
                raise ValueError(
                    f"exact replacement {fitted!r} still contains --contains value {text!r}. "
                    "A later substring pass would change it."
                )
        exact_rules.append(
            Rule(
                "exact",
                old,
                fitted,
                tuple(form for form, _replacement in pairs),
                tuple(replacement for _form, replacement in pairs),
            )
        )

    exact_forms = {form for rule in exact_rules for form in rule.forms}
    for text in contains:
        if text in exact_forms:
            raise ValueError(
                f"{text!r} is both a --contains value and an --exact search string"
            )
    for rule in exact_rules:
        for other in exact_rules:
            if other.old == rule.old:
                continue
            for replacement in rule.replacements:
                for form in other.forms:
                    if form in replacement:
                        raise ValueError(
                            f"exact replacement {replacement!r} contains exact search {form!r}. "
                            "A later pass would change it."
                        )

    blocked = (
        contains
        + [rule.old for rule in exact_rules]
        + [rule.new for rule in exact_rules]
    )
    contain_rules = []
    for text in sorted(contains, key=len, reverse=True):
        token = obfuscated_token(text, blocked, seed)
        forms = separator_forms(text)
        contain_rules.append(
            Rule("contains", text, token, forms, tuple(token for _form in forms))
        )
    exact_rules.sort(key=lambda rule: len(rule.old), reverse=True)
    return exact_rules + contain_rules


def rewrite_apk(
    source: str | Path,
    dest: str | Path,
    contains: list[str] | None = None,
    exact: list[tuple[str, str]] | None = None,
    *,
    seed: str = "softcloak",
    fit: str = "error",
    pad_char: str = " ",
    allow_missing: bool = False,
    dry_run: bool = False,
    keystore: str | Path | None = None,
    storepass: str | None = None,
    keypass: str | None = None,
    alias: str = "repack",
) -> RewriteResult:
    """Replace text in an APK and re-sign it.

    ``contains`` replaces each substring with one generated token of the same
    length. ``exact`` is a list of ``(old, new)`` pairs. ``new`` must be the
    same length as ``old`` unless ``fit`` is ``"pad"`` or ``"clip"``.

    The returned :class:`RewriteResult` lists each replacement on ``rules``
    and how many UTF-8 and UTF-16 matches changed in ``counts``. ``output``
    is the signed APK, or ``None`` when ``dry_run`` is true.
    """
    source_path = Path(source)
    dest_path = Path(dest)
    if not source_path.is_file():
        raise ValueError(f"APK not found: {source_path}")
    rules = build_rules(contains, exact, seed=seed, fit=fit, pad_char=pad_char)

    with zipfile.ZipFile(source_path) as archive:
        stored = [(info, archive.read(info.filename)) for info in archive.infolist()]

    avoid_token_collisions(
        rules,
        [data for info, data in stored if not is_signature_entry(info.filename)],
        seed,
    )

    warnings: list[str] = []
    for rule in rules:
        if len(rule.old) < 4:
            warnings.append(f"{rule.old!r} is very short and can match unrelated bytes")
    missing: list[str] = []
    searchable = []
    for info, data in stored:
        if is_signature_entry(info.filename) or _skipped(info.filename):
            hits = [rule.old for rule in rules if rule_present(data, rule)]
            if hits:
                reason = (
                    "signature file"
                    if is_signature_entry(info.filename)
                    else "skipped binary file"
                )
                warnings.append(
                    f"{info.filename} ({reason}) still contains: {', '.join(hits)}. "
                    "Those bytes were left unchanged."
                )
            continue
        searchable.append((info, data))

    for rule in rules:
        if not any(rule_present(data, rule) for _, data in searchable):
            missing.append(rule.old)
    if missing and not allow_missing:
        joined = ", ".join(repr(item) for item in missing)
        raise ValueError(f"no occurrences found for: {joined}")

    totals = {rule.old: [0, 0] for rule in rules}
    rewritten: list[tuple[zipfile.ZipInfo, bytes]] = []
    for info, data in searchable:
        updated, counts = apply_rules(data, rules)
        for key, (utf8_count, utf16_count) in counts.items():
            totals[key][0] += utf8_count
            totals[key][1] += utf16_count
        if updated != data and info.filename.endswith(".dex"):
            updated = fix_dex(updated)
        rewritten.append((info, updated))

    result_counts = {key: (value[0], value[1]) for key, value in totals.items()}
    if dry_run:
        return RewriteResult(None, rules, result_counts, warnings, dry_run=True)

    same_target = source_path.resolve() == dest_path.resolve()
    output = dest_path
    if same_target:
        output = dest_path.with_name(dest_path.name + ".tmp")

    with tempfile.TemporaryDirectory() as temp_dir:
        unsigned = Path(temp_dir) / "unsigned.apk"
        build_zip(rewritten, unsigned)
        warnings.extend(
            sign_apk(
                unsigned,
                output,
                keystore=Path(keystore) if keystore else None,
                storepass=storepass,
                keypass=keypass,
                alias=alias,
            )
        )
    if same_target:
        os.replace(output, dest_path)
        output = dest_path
    return RewriteResult(output, rules, result_counts, warnings, dry_run=False)
