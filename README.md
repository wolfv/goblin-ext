# goblin-ext

[![Crates.io](https://img.shields.io/crates/v/goblin-ext.svg)](https://crates.io/crates/goblin-ext)
[![Documentation](https://docs.rs/goblin-ext/badge.svg)](https://docs.rs/goblin-ext)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/wolfv/goblin-ext/actions/workflows/ci.yml/badge.svg)](https://github.com/wolfv/goblin-ext/actions/workflows/ci.yml)

Binary modification utilities built on [goblin](https://crates.io/crates/goblin).

This crate provides programmatic access to binary modification workflows typically done via command-line tools:

- **Mach-O binaries** (macOS/iOS): Functionality similar to Apple's `install_name_tool`
- **ELF binaries** (Linux/BSD): Functionality similar to `patchelf`

## Features

- Modify dylib install names and dependencies (Mach-O)
- Add, remove, and modify runtime search paths (rpath)
- Change SONAME entries (ELF)
- Convert between RPATH and RUNPATH (ELF)
- Ad-hoc code signing support (Mach-O, with `codesign` feature)
- Support for both 32-bit and 64-bit binaries
- Support for FAT/universal binaries (Mach-O)
- Smart relocation strategies to handle growing sections
- `no_std` compatible (with `alloc`)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
goblin-ext = "0.1"
```

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Standard library support |
| `mach` | Yes | Mach-O binary support |
| `elf` | Yes | ELF binary support |
| `codesign` | No | Ad-hoc code signing for Mach-O binaries |

## Usage

### Mach-O Example

```rust
use goblin_ext::MachOWriter;

let data = std::fs::read("libfoo.dylib")?;
let mut writer = MachOWriter::new(data)?;

// Change the install name
writer.change_id("@rpath/libfoo.dylib")?;

// Modify a dependency path
writer.change_dylib("/usr/lib/libold.dylib", "/usr/local/lib/libnew.dylib")?;

// Add an rpath
writer.add_rpath("@loader_path/../lib")?;

// Build the modified binary
let output = writer.build()?;
std::fs::write("libfoo_modified.dylib", output)?;
```

### ELF Example

```rust
use goblin::elf::Elf;
use goblin_ext::ElfWriter;

let data = std::fs::read("binary")?;
let elf = Elf::parse(&data)?;
let mut writer = ElfWriter::new(&data, &elf)?;

// Set the RUNPATH
writer.set_rpath("/usr/local/lib")?;

// Or set multiple paths
writer.set_rpath("/usr/local/lib:/opt/lib")?;

// Write the modified binary
let output = writer.write()?;
std::fs::write("binary_modified", output)?;
```

### FAT Binary Support (Mach-O)

```rust
use goblin_ext::modify_fat_binary;

let data = std::fs::read("universal.dylib")?;
let output = modify_fat_binary(&data, |writer| {
    writer.change_id("@rpath/universal.dylib")?;
    writer.add_rpath("@loader_path/../lib")?;
    Ok(())
})?;
std::fs::write("universal_modified.dylib", output)?;
```

## API Overview

### MachOWriter

| Method | Description |
|--------|-------------|
| `get_id()` | Get the binary's install name |
| `change_id(name)` | Change the dylib install name |
| `get_dylibs()` | List all dylib dependencies |
| `change_dylib(old, new)` | Modify a dependency path |
| `delete_dylib(name)` | Remove a dependency |
| `add_dylib(name, kind)` | Add a new dependency |
| `get_rpaths()` | List all runtime search paths |
| `add_rpath(path)` | Add an rpath |
| `delete_rpath(path)` | Remove an rpath |
| `change_rpath(old, new)` | Modify an rpath |
| `build()` | Serialize the modified binary |

### ElfWriter

| Method | Description |
|--------|-------------|
| `set_rpath(path)` | Set DT_RUNPATH (or DT_RPATH) |
| `set_rpath_forced(path)` | Force DT_RPATH instead of DT_RUNPATH |
| `set_soname(name)` | Set DT_SONAME |
| `remove_rpath()` | Remove DT_RPATH |
| `remove_runpath()` | Remove DT_RUNPATH |
| `rpath_to_runpath()` | Convert DT_RPATH to DT_RUNPATH |
| `runpath_to_rpath()` | Convert DT_RUNPATH to DT_RPATH |
| `write()` | Write the modified binary |

## Examples

The crate includes two example CLI tools:

### install_name_tool

A Rust implementation of Apple's `install_name_tool`:

```bash
cargo run --example install_name_tool --features codesign -- \
    -id @rpath/libfoo.dylib \
    -add_rpath @loader_path/../lib \
    -change /usr/lib/libold.dylib /usr/local/lib/libnew.dylib \
    libfoo.dylib -o libfoo_modified.dylib
```

### patchelf

A Rust implementation of `patchelf`:

```bash
cargo run --example patchelf -- set-rpath /usr/local/lib binary -o binary_modified
cargo run --example patchelf -- print-rpath binary
cargo run --example patchelf -- rpath-to-runpath binary -o binary_modified
```

## Use Cases

- **CI/CD pipelines**: Automate binary patching as part of build processes
- **Cross-compilation**: Fix library paths for different deployment environments
- **Package management**: Relocate binaries to new install prefixes
- **Development**: Test binaries with different library versions

## Minimum Supported Rust Version

This crate requires Rust 1.90.0 or later.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
