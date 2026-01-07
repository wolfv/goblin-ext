//! # goblin-ext
//!
//! Binary modification utilities built on [goblin](https://crates.io/crates/goblin).
//!
//! This crate provides functionality similar to:
//! - Apple's `install_name_tool` for Mach-O binaries (with `mach` feature)
//! - `patchelf` for ELF binaries (with `elf` feature)
//!
//! ## Mach-O Example
//!
//! ```no_run
//! use goblin_ext::MachOWriter;
//!
//! let data = std::fs::read("libfoo.dylib").unwrap();
//! let mut writer = MachOWriter::new(data).unwrap();
//!
//! // Change the install name
//! writer.change_id("@rpath/libfoo.dylib").unwrap();
//!
//! // Add an rpath
//! writer.add_rpath("@loader_path/../lib").unwrap();
//!
//! // Build the modified binary
//! let output = writer.build().unwrap();
//! std::fs::write("libfoo_modified.dylib", output).unwrap();
//! ```
//!
//! ## ELF Example
//!
//! ```no_run
//! use goblin::elf::Elf;
//! use goblin_ext::ElfWriter;
//!
//! let data = std::fs::read("binary").unwrap();
//! let elf = Elf::parse(&data).unwrap();
//! let mut writer = ElfWriter::new(&data, &elf).unwrap();
//!
//! // Set the RUNPATH
//! writer.set_rpath("/usr/local/lib").unwrap();
//!
//! // Write the modified binary
//! let output = writer.write().unwrap();
//! std::fs::write("binary_modified", output).unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Mach-O writer module (macOS/iOS binaries)
#[cfg(feature = "mach")]
pub mod macho_writer;

// ELF writer module (Linux/BSD binaries)
#[cfg(feature = "elf")]
pub mod elf_writer;

// Code signing module (macOS ad-hoc signing)
#[cfg(all(feature = "mach", feature = "codesign"))]
pub mod codesign;

// Re-export Mach-O types at crate root for convenience
#[cfg(feature = "mach")]
pub use macho_writer::{modify_fat_binary, DylibInfo, DylibKind, MachOInfo, MachOWriter};

// Re-export codesign types at crate root for convenience
#[cfg(all(feature = "mach", feature = "codesign"))]
pub use codesign::{
    adhoc_sign, adhoc_sign_file, constants as codesign_constants, extract_entitlements,
    generate_adhoc_signature, is_linker_signed, AdhocSignOptions, Entitlements,
};

// Re-export ELF types at crate root for convenience
#[cfg(feature = "elf")]
pub use elf_writer::ElfWriter;
