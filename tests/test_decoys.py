import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from softcloak.decoys import build_decoy_dex
from softcloak.rewrite import fix_dex, rewrite_apk


class DecoyTests(unittest.TestCase):
    def test_same_seed_is_stable_and_another_seed_differs(self):
        first, names, seed = build_decoy_dex(3, seed="alpha")
        again, again_names, _seed = build_decoy_dex(3, seed="alpha")
        other, other_names, _seed = build_decoy_dex(3, seed="beta")
        self.assertEqual(seed, "alpha")
        self.assertEqual(first, again)
        self.assertEqual(names, again_names)
        self.assertNotEqual(first, other)
        self.assertNotEqual(names, other_names)
        self.assertEqual(first, fix_dex(first))

    def test_generated_dex_has_no_tool_name(self):
        dex, names, _seed = build_decoy_dex(4, seed="alpha")
        lowered = dex.lower()
        for marker in (b"softcloak", b"decoy", b"herring"):
            self.assertNotIn(marker, lowered)
        self.assertEqual(len(names), 4)
        self.assertTrue(all("." in name for name in names))

    def test_avoids_existing_class_descriptors(self):
        _dex, names, _seed = build_decoy_dex(1, seed="alpha")
        blocked = "L" + names[0].replace(".", "/") + ";"
        _other, other_names, _seed = build_decoy_dex(1, seed="alpha", avoid={blocked})
        self.assertNotEqual(names, other_names)

    def test_rewrite_keeps_original_dex_and_adds_decoys(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.apk"
            plain = root / "plain.apk"
            extra = root / "extra.apk"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "classes.dex", b"dex\n035\x00" + b"\x00" * 32 + b"com.example"
                )
            rewrite_apk(source, plain, contains=["com.example"], decoys=0)
            result = rewrite_apk(
                source,
                extra,
                contains=["com.example"],
                decoys=2,
                decoy_seed="alpha",
            )
            with (
                zipfile.ZipFile(plain) as plain_zip,
                zipfile.ZipFile(extra) as extra_zip,
            ):
                self.assertEqual(
                    plain_zip.read("classes.dex"),
                    extra_zip.read("classes.dex"),
                )
                self.assertIn("classes2.dex", extra_zip.namelist())
                added = extra_zip.read("classes2.dex")
            self.assertEqual(len(result.decoy_classes), 2)
            self.assertEqual(result.decoy_seed, "alpha")
            self.assertEqual(added, fix_dex(added))
            dexdump = _dexdump()
            if dexdump is None:
                return
            dump = root / "classes2.dex"
            dump.write_bytes(added)
            checked = subprocess.run(
                [dexdump, str(dump)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertNotIn("ERROR", checked.stdout)


def _dexdump() -> str | None:
    found = shutil.which("dexdump")
    if found:
        return found
    root = Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools"
    candidates = sorted(root.glob("*/dexdump.exe")) if root.is_dir() else []
    if candidates:
        return str(candidates[-1])
    return None


if __name__ == "__main__":
    unittest.main()
