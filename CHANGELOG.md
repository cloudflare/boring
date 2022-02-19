# Change Log

## [Unreleased]

## [v2.0.0] - 2021-12-16

### Changed

* Updated `foreign-types` from 0.3 to 0.5. This is technically a breaking change if you used `foreign-types` in your own crate, but in practice this shouldn't have a large impact.
* Removed unused `*Ref` structs; these served no purpose and were not useful.
* Removed unused `tempdir` dependency
