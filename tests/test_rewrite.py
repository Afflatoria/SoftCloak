import hashlib
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from softcloak.rewrite import (
    apply_rules,
    build_rules,
    fix_dex,
    obfuscated_token,
    rewrite_apk,
)


class TokenTests(unittest.TestCase):
    def test_token_matches_length_and_avoids_blocked_text(self):
        blocked = ["uncrackable1", "owasp", "Bernhard"]
        token = obfuscated_token("uncrackable1", blocked, "seed")
        self.assertEqual(len(token), len("uncrackable1"))
        self.assertTrue(token.isascii())
        self.assertEqual(token, obfuscated_token("uncrackable1", blocked, "seed"))
        for item in blocked:
            self.assertNotIn(item.lower(), token.lower())


class RuleTests(unittest.TestCase):
    def test_exact_keeps_a_chosen_string_and_contains_rewrites_the_rest(self):
        rules = build_rules(
            ["uncrackable1"],
            [("owasp.mstg.uncrackable1", "com.example.localmsgapp")],
            seed="seed",
            fit="error",
            pad_char=" ",
        )
        data = b"owasp.mstg.uncrackable1 plus uncrackable1"
        updated, counts = apply_rules(data, rules)
        self.assertIn(b"com.example.localmsgapp", updated)
        self.assertNotIn(b"uncrackable1", updated)
        self.assertNotIn(b"owasp.mstg.uncrackable1", updated)
        self.assertEqual(counts["owasp.mstg.uncrackable1"], (1, 0))
        self.assertEqual(counts["uncrackable1"], (1, 0))

    def test_dotted_substring_replaces_every_dex_slash_copy(self):
        rules = build_rules(
            ["sg.vantagepoint"], None, seed="seed", fit="error", pad_char=" "
        )
        data = (
            b"Lsg/vantagepoint/a/a; Lsg/vantagepoint/uncrackable1/MainActivity; "
            b"sg.vantagepoint.MainActivity"
        )
        data += "prefix sg.vantagepoint.MainActivity".encode("utf-16le")
        updated, counts = apply_rules(data, rules)
        self.assertNotIn(b"vantagepoint", updated)
        self.assertNotIn("vantagepoint".encode("utf-16le"), updated)
        self.assertEqual(counts["sg.vantagepoint"], (3, 1))
        self.assertIn(b"L", updated)
        self.assertIn(b"/a/a;", updated)

    def test_utf16_occurrence_is_replaced(self):
        rules = build_rules(["owasp"], None, seed="seed", fit="error", pad_char=" ")
        data = "pkg owasp end".encode("utf-16le")
        updated, counts = apply_rules(data, rules)
        self.assertEqual(counts["owasp"], (0, 1))
        self.assertNotIn("owasp".encode("utf-16le"), updated)

    def test_length_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            build_rules(
                None,
                [("short", "much longer text")],
                seed="seed",
                fit="error",
                pad_char=" ",
            )

    def test_pad_fit_reaches_the_original_length(self):
        rules = build_rules(
            None, [("abcdef", "xy")], seed="seed", fit="pad", pad_char="."
        )
        self.assertEqual(rules[0].new, "xy....")


class DexTests(unittest.TestCase):
    def test_checksum_matches_the_patched_bytes(self):
        raw = bytearray(b"dex\n035\x00" + b"\x00" * 120)
        raw.extend(b"uncrackable1")
        rules = build_rules(
            ["uncrackable1"], None, seed="seed", fit="error", pad_char=" "
        )
        updated, _counts = apply_rules(bytes(raw), rules)
        patched = fix_dex(updated)
        self.assertNotIn(b"uncrackable1", patched)
        checksum = struct.unpack_from("<I", patched, 8)[0]
        self.assertEqual(checksum, zlib.adler32(patched[12:]) & 0xFFFFFFFF)
        self.assertEqual(hashlib.sha1(patched[32:]).digest(), patched[12:32])


class ApkTests(unittest.TestCase):
    def test_rewrite_signs_and_removes_requested_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.apk"
            dest = root / "sample-out.apk"
            dex = bytearray(b"dex\n035\x00" + b"\x00" * 120)
            dex.extend(b"Lsg/vantagepoint/uncrackable1/MainActivity;")
            manifest = "name=owasp.mstg.uncrackable1".encode("utf-16le")
            resources = b"Thanks to Bernhard Mueller for the demo."
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("classes.dex", bytes(dex))
                archive.writestr("AndroidManifest.xml", manifest)
                archive.writestr("resources.arsc", resources)
                archive.writestr("res/icon.png", b"\x89PNG uncrackable1")
                archive.writestr("META-INF/services/demo", b"keep-me uncrackable1")

            result = rewrite_apk(
                source,
                dest,
                contains=["uncrackable1", "vantagepoint", "owasp"],
                exact=[("Bernhard Mueller", "Replacement Text")],
            )

            self.assertTrue(dest.is_file())
            self.assertIn("res/icon.png", " ".join(result.warnings))
            with zipfile.ZipFile(dest) as archive:
                names = set(archive.namelist())
                blob = b"".join(
                    archive.read(name)
                    for name in archive.namelist()
                    if not name.startswith("META-INF/")
                )
                self.assertIn("META-INF/services/demo", names)
                self.assertNotIn(b"uncrackable1", blob)
                self.assertNotIn(b"vantagepoint", blob)
                self.assertNotIn("owasp".encode("utf-16le"), blob)
                self.assertNotIn(b"Bernhard Mueller", blob)
                self.assertIn(b"Replacement Text", blob)
                dex_out = archive.read("classes.dex")
                checksum = struct.unpack_from("<I", dex_out, 8)[0]
                self.assertEqual(checksum, zlib.adler32(dex_out[12:]) & 0xFFFFFFFF)
                self.assertIn(b"keep-me", archive.read("META-INF/services/demo"))
                self.assertNotIn(
                    b"uncrackable1", archive.read("META-INF/services/demo")
                )


class PublicApiTests(unittest.TestCase):
    def test_import_can_plan_a_rewrite(self):
        from softcloak import rewrite_apk

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.apk"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "classes.dex", b"dex\n035\x00" + b"\x00" * 32 + b"com.example"
                )
            result = rewrite_apk(
                source,
                root / "out.apk",
                contains=["com.example"],
                dry_run=True,
            )
            self.assertIsNone(result.output)
            self.assertEqual(result.rules[0].old, "com.example")
            self.assertEqual(len(result.rules[0].new), len("com.example"))
            self.assertGreater(result.counts["com.example"][0], 0)


if __name__ == "__main__":
    unittest.main()
