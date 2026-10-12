# SoftCloak

The goal of this repository is to try and make reverse engineering more difficult. Currently only
focused on APK files but will eventually move on to IPA files, binaries, firmware, and other software.

SoftCloak replaces text inside an APK, then signs the rebuilt package. Substring matches are swapped for one generated token of the same length. Exact matches are swapped for text you choose. The APK is signed with a new jar signature.

Same-length replacements keep the DEX, manifest, and resource table aligned, so the file can still be installed.

## Install

A JDK is required. `keytool` and `jarsigner` must be on `PATH`.

From the project directory:

```bash
pip install -e ".[dev]"
```

The `dev` extra installs Ruff. The test suite runs `ruff check` and `ruff format --check`.

## Use

Generate a token for every occurrence of a substring:

```bash
softcloak app.apk -o rebuilt.apk --contains com.example --contains CompanyName
```

Replace one exact string with your own text. The new text has to be the same length:

```bash
softcloak app.apk -o rebuilt.apk --exact "Old full sentence" "New full sentence"
```

Both can be combined. Exact replacements run first, then substring tokens. The command prints each mapping and checks the signature before it finishes.

```bash
softcloak app.apk -o rebuilt.apk --dry-run --contains CompanyName
softcloak app.apk -o rebuilt.apk --exact "abcdef" "xy" --fit pad
softcloak app.apk -o rebuilt.apk --contains CompanyName --keystore my.keystore --storepass secret --alias mykey
```

`--fit pad` fills a shorter exact replacement. `--fit clip` cuts a longer one and pads a shorter one. The default is to stop when the lengths differ.

`--contains` replaces that text wherever it sits inside a longer string, in every file, in both UTF-8 and UTF-16. A dotted name also rewrites the DEX form with slashes, so `com.example` changes `Lcom/example/...` as well. Matching is case-sensitive. Pass `AppName` and `appname` separately. Patterns shorter than 4 characters are allowed, but they can hit unrelated bytes.

Image, audio, font, and native-library entries are left unchanged. Signature files are removed and replaced by the new signature. Other `META-INF` files are kept and edited.

## What can break the app

SoftCloak changes only the text you pass in. A same-length rename of your own package or class name can still install and run, because the manifest and `classes.dex` are updated together.

The app can crash or fail a lookup when a replacement has to match something that was not changed:

- Framework names such as `android` or `java` appear inside system class names. Replacing them makes those calls invalid. A short warning exists for patterns under 4 characters, and it does not stop the run. `android` is long enough to pass through with no warning.
- Resource paths, such as `res/layout/...`, must match the file names in the APK. SoftCloak does not rename those files.
- Native libraries are left unchanged. If code now looks up a new name and the library still has the old one, that call fails.
- Intent actions, content-provider authorities, and server URLs fail when only one side of the match is replaced.
