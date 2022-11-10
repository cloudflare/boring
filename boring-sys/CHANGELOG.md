# Change Log

## [Unreleased]

## [v2.1.0] - 2022-09-16

### Added

* Support using a FIPS-certified boringssl. You can enable this with `--features fips`.
* Support `aarch64-apple-ios-sim` targets

### Changed

* Updated `bindgen` to `1.60`
* Updated `boring-sys` to f1c75347daa2ea81a941e953f2263e0a4d970c8d. In particular, this makes boring compatible with `quiche 0.12`.

### Fixed

* Use the Android NDK sysroot when running bindgen
* Only apply the MSVC generator hack when targeting MSVC, not all Windows targets

## [v2.0.0] - 2021-12-16

### Added

* Allow using pre-built binaries of `bssl` using the `BORING_BSSL_PATH` env variable
* Automatically fetch the `boringssl` submodule if it doesn't yet exist

### Changed

* Removed unused `PasswordCallback` type
* Disable unused bindgen dependencies
* Update `bindgen` and `bytes` dependencies
* 