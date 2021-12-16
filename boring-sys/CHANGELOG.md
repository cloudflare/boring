# Change Log

## [Unreleased]

## [v2.0.0] - 2021-12-16

### Added

* Allow using pre-built binaries of `bssl` using the `BORING_BSSL_PATH` env variable
* Automatically fetch the `boringssl` submodule if it doesn't yet exist

### Changed

* Removed unused `PasswordCallback` type
* Disable unused bindgen dependencies
* Update `bindgen` and `bytes` dependencies
* 