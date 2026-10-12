# SoftCloak

The goal of this repository is to try and make reverse engineering more difficult. Currently only
focused on APK files but will eventually move on to IPA files, binaries, firmware, and other software.

SoftCloak replaces text inside an APK, then signs the rebuilt package. Substring matches are swapped for one generated token of the same length. Exact matches are swapped for text you choose. The APK is signed with a new JAR v1 signature and an APK v2 signature.

Same-length replacements keep the DEX, manifest, and resource table aligned, so the file can still be installed.

## Install

```bash
pip install softcloak
```

That install is enough to replace strings and sign the APK. SoftCloak creates the signing key itself and writes a JAR v1 signature plus an APK v2 signature. A JDK and the Android SDK are not required.

If `softcloak` is not found after that, the scripts directory is not on `PATH`. Use `python -m softcloak` in the examples below.

## Command line

Generate a token for every occurrence of a substring:

```bash
python -m softcloak app.apk -o rebuilt.apk --contains com.example --contains CompanyName
```

Replace one exact string with your own text. The new text has to be the same length:

```bash
python -m softcloak app.apk -o rebuilt.apk --exact "Old full sentence" "New full sentence"
```

Both can be combined. Exact replacements run first, then substring tokens. The command prints each mapping and checks the signature before it finishes.

```bash
python -m softcloak app.apk -o rebuilt.apk --dry-run --contains CompanyName
python -m softcloak app.apk -o rebuilt.apk --exact "abcdef" "xy" --fit pad
```

`--fit pad` fills a shorter exact replacement. `--fit clip` cuts a longer one and pads a shorter one. The default is to stop when the lengths differ.

`--contains` replaces that text wherever it sits inside a longer string, in every file, in both UTF-8 and UTF-16. A dotted name also rewrites the DEX form with slashes, so `com.example` changes `Lcom/example/...` as well. An exact replacement does the same, and keeps the separator you would expect: `com.example` to `org.example` also rewrites `com/example` to `org/example`. Matching is case-sensitive. Pass `AppName` and `appname` separately. Patterns shorter than 4 characters are allowed, but they can hit unrelated bytes, and SoftCloak prints a warning.

Image, audio, font, and native-library files are copied into the output unchanged. If a search string still occurs inside one of them, SoftCloak prints a warning and does not edit those bytes. A stored native library is repacked so its bytes start on a 16384-byte boundary, which covers 4 KB and 16 KB memory pages. Signature files are removed and replaced by the new signature. Other `META-INF` files are kept and edited.

SoftCloak generates an RSA key and a self-signed certificate with subject `CN=SoftCloak`, then signs the APK with it. The default alias is `repack`. The zip writer uses the classic zip format, so an archive over 4 GB or with more than 65535 entries is out of scope.

## Python

Skip the command line and call the same operation from a script:

```python
from softcloak import rewrite_apk

result = rewrite_apk(
    "app.apk",
    "rebuilt.apk",
    contains=["com.example", "CompanyName"],
    exact=[("Old full sentence", "New full sentence")],
)
for rule in result.rules:
    utf8_count, utf16_count = result.counts[rule.old]
    print(f"{rule.old} -> {rule.new}  utf8={utf8_count} utf16={utf16_count}")
print(result.output)
```

Preview the mapping without writing a file:

```python
result = rewrite_apk(
    "app.apk",
    "rebuilt.apk",
    contains=["CompanyName"],
    dry_run=True,
)
```

`result.counts` maps each original string to `(utf8_matches, utf16_matches)`. `result.warnings` lists matches that were left unchanged. `result.output` is the signed APK, or `None` when `dry_run` is true.

Other arguments match the command line: `seed`, `fit` (`"error"`, `"pad"`, or `"clip"`), `pad_char`, and `allow_missing`. Omit `keystore` and SoftCloak creates the key.

## Development

From a checkout of this repository:

```bash
pip install -e ".[dev]"
```

The `dev` extra installs Ruff. The test suite runs `ruff check` and `ruff format --check`.

## What can break the app

SoftCloak changes only the text you pass in. A same-length rename of your own package or class name can still install and run, because the manifest and `classes.dex` are updated together.

The app can crash or fail a lookup when a replacement has to match something that was not changed:

- Framework names such as `android` or `java` appear inside system class names. Replacing them makes those calls invalid. A short warning exists for patterns under 4 characters, and it does not stop the run. `android` is long enough to pass through with no warning.
- Resource paths, such as `res/layout/...`, must match the file names in the APK. SoftCloak does not rename those files.
- Native libraries are left unchanged. If code now looks up a new name and the library still has the old one, that call fails.
- Intent actions, content-provider authorities, and server URLs fail when only one side of the match is replaced.
- The rebuilt APK is signed with a new certificate. Android will not install it over a copy signed by the previous certificate. Uninstall the old copy first.
