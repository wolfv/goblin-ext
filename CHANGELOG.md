# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-03

### Added

- Initial release
- `MachOWriter` for Mach-O binary modification
  - Install name (dylib ID) modification
  - Dylib dependency management (add, remove, change)
  - Rpath management (add, remove, change)
  - FAT/universal binary support
  - Ad-hoc code signing support (with `codesign` feature)
  - Automatic segment relocation for growing load commands
- `ElfWriter` for ELF binary modification
  - RPATH/RUNPATH modification
  - SONAME modification
  - RPATH to RUNPATH conversion and vice versa
  - Smart write strategies (slack space, append, prepend)
  - Support for 32-bit and 64-bit ELF
- Example CLI tools
  - `install_name_tool`: Apple's install_name_tool clone
  - `patchelf`: patchelf clone
- `no_std` support with `alloc`

[Unreleased]: https://github.com/wolfv/goblin-ext/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wolfv/goblin-ext/releases/tag/v0.1.0
