"""Command line for SoftCloak."""

from __future__ import annotations

import argparse
import sys

from softcloak.rewrite import rewrite_apk


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="softcloak",
        description=(
            "Replace substrings in an APK with a same-length obfuscated token, "
            "replace exact strings with text you choose, and re-sign the APK."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  softcloak app.apk -o rebuilt.apk --contains com.example --contains CompanyName\n"
            '  softcloak app.apk -o rebuilt.apk --exact "Old full sentence" "New full sentence"\n'
        ),
    )
    parser.add_argument("apk", help="input APK")
    parser.add_argument("-o", "--output", required=True, help="signed output APK")
    parser.add_argument(
        "--contains",
        action="append",
        default=[],
        metavar="SUBSTRING",
        help="replace every occurrence of SUBSTRING with one generated token of the same length",
    )
    parser.add_argument(
        "--exact",
        nargs=2,
        action="append",
        default=[],
        metavar=("OLD", "NEW"),
        help="replace the exact text OLD with NEW. NEW must be the same length unless --fit is set",
    )
    parser.add_argument("--seed", default="softcloak", help="seed for generated tokens")
    parser.add_argument(
        "--fit",
        choices=("error", "pad", "clip"),
        default="error",
        help="what to do when an exact replacement has a different length (default: error)",
    )
    parser.add_argument(
        "--pad-char", default=" ", help="character used by --fit pad or --fit clip"
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="do not fail when a search string is absent",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report replacements without writing an APK",
    )
    parser.add_argument(
        "--keystore",
        help="existing keystore. A temporary key is generated when omitted",
    )
    parser.add_argument("--storepass", help="keystore password")
    parser.add_argument("--keypass", help="key password. Defaults to --storepass")
    parser.add_argument("--alias", default="repack", help="key alias")
    parser.add_argument(
        "--decoys",
        type=int,
        default=0,
        help="add this many unused classes with random names and bytecode",
    )
    parser.add_argument(
        "--decoy-seed",
        help="seed for --decoys. Omit it to pick a new random seed every run",
    )
    return parser


def _print_result(result) -> None:
    for rule in result.rules:
        utf8_count, utf16_count = result.counts.get(rule.old, (0, 0))
        replacements = rule.replacements or tuple(rule.new for _form in rule.forms)
        extras = [
            f"{form!r} -> {replacement!r}"
            for form, replacement in zip(rule.forms, replacements, strict=True)
            if form != rule.old
        ]
        suffix = f" also {', '.join(extras)}" if extras else ""
        print(
            f"{rule.kind} {rule.old!r} -> {rule.new!r}{suffix} "
            f"(utf8={utf8_count}, utf16={utf16_count})"
        )
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if result.dry_run:
        print("dry run: no APK written")
    else:
        print(f"wrote {result.output}")
        print("signature verified")
    if result.decoy_classes:
        print(f"decoy seed {result.decoy_seed}")
        for name in result.decoy_classes:
            print(f"decoy {name}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = rewrite_apk(
            args.apk,
            args.output,
            contains=args.contains,
            exact=[tuple(pair) for pair in args.exact],
            seed=args.seed,
            fit=args.fit,
            pad_char=args.pad_char,
            allow_missing=args.allow_missing,
            dry_run=args.dry_run,
            keystore=args.keystore,
            storepass=args.storepass,
            keypass=args.keypass,
            alias=args.alias,
            decoys=args.decoys,
            decoy_seed=args.decoy_seed,
        )
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
