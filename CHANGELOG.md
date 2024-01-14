# CHANEGLOG

## v0.3.0 (2024-01-14)

### Features

* support new encryption table ([b484303](https://github.com/KaDw/pk-crypt-rs/commit/b484303))
* xor bruteforce plaintext is now supplied by the user ([b484303](https://github.com/KaDw/pk-crypt-rs/commit/b484303))

### Fix

* Remove decrypt validation. It was done by reading hardcoded phrase from a file, it happened that the file could be empty. ([b484303](https://github.com/KaDw/pk-crypt-rs/commit/b484303)). Thanks to Ryuk for reporting this

### Refactor

* decrypt and encrypt are now part of PkCrypt impl ([b484303](https://github.com/KaDw/pk-crypt-rs/commit/b484303))
* new readme, add section about vscode ([56014e4](https://github.com/KaDw/pk-crypt-rs/commit/56014e4))

### BREAKING CHANGE

* removed -f option, specify -i and -o instead ([b484303](https://github.com/KaDw/pk-crypt-rs/commit/b484303))

## v0.2.0 (2023-05-07)

### Features

* password can be supplied as bytes (hex) ([af826c2](https://github.com/KaDw/pk-crypt-rs/commit/af826c2700252516ab7b5ebbb3823adfb4a3f957)), closes [#1](https://github.com/KaDw/pk-crypt-rs/issues/1)

### Refactor

* refactor: use zip-rs encrypt instead of pkzipc ([63e05f9](https://github.com/KaDw/pk-crypt-rs/commit/63e05f9))
* add release link to readme ([6bb7021](https://github.com/KaDw/pk-crypt-rs/commit/6bb7021))

## v0.1.0 (2023-05-04)

Initial version
