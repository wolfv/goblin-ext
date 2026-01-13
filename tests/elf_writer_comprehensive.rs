//! Comprehensive tests for ElfWriter to ensure correctness and robustness.
//!
//! These tests verify:
//! - ELF structural integrity after modification
//! - Alignment invariants are maintained
//! - Dynamic section consistency
//! - Binary executability
//! - Edge cases and stress tests

use goblin::elf::program_header::PT_LOAD;
use goblin::elf::Elf;
use goblin_ext::ElfWriter;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn test_assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("assets")
}

fn get_test_binary() -> Option<Vec<u8>> {
    let path = test_assets_dir().join("test_elf_x86_64");
    if path.exists() {
        Some(fs::read(&path).expect("Failed to read test binary"))
    } else {
        None
    }
}

/// Comprehensive ELF validation
fn validate_elf_comprehensive(data: &[u8], context: &str) -> Result<(), String> {
    let elf = Elf::parse(data).map_err(|e| format!("{context}: Failed to parse ELF: {e}"))?;

    // 1. Validate ELF header
    if elf.header.e_phnum == 0 {
        return Err(format!("{context}: No program headers"));
    }

    // 2. Validate all PT_LOAD segments have proper alignment
    for (i, phdr) in elf.program_headers.iter().enumerate() {
        if phdr.p_type == PT_LOAD {
            // Check alignment is power of 2
            if phdr.p_align > 0 && !phdr.p_align.is_power_of_two() {
                return Err(format!(
                    "{}: PT_LOAD[{}] alignment 0x{:x} is not power of 2",
                    context, i, phdr.p_align
                ));
            }

            // Check alignment invariant: (p_vaddr - p_offset) % p_align == 0
            if phdr.p_align > 0 {
                let diff = phdr.p_vaddr.wrapping_sub(phdr.p_offset);
                if diff % phdr.p_align != 0 {
                    return Err(format!(
                        "{}: PT_LOAD[{}] violates alignment invariant: vaddr=0x{:x}, offset=0x{:x}, align=0x{:x}",
                        context, i, phdr.p_vaddr, phdr.p_offset, phdr.p_align
                    ));
                }
            }

            // Check segment doesn't extend beyond file
            let seg_end = phdr.p_offset.saturating_add(phdr.p_filesz) as usize;
            if seg_end > data.len() {
                return Err(format!(
                    "{}: PT_LOAD[{}] extends beyond file: offset=0x{:x}, filesz=0x{:x}, file_len=0x{:x}",
                    context, i, phdr.p_offset, phdr.p_filesz, data.len()
                ));
            }
        }
    }

    // 3. Validate section headers
    for (i, shdr) in elf.section_headers.iter().enumerate() {
        if i == 0 {
            continue; // Skip NULL section
        }

        // Check section doesn't extend beyond file (except NOBITS)
        if shdr.sh_type != goblin::elf::section_header::SHT_NOBITS {
            let sec_end = shdr.sh_offset.saturating_add(shdr.sh_size) as usize;
            if sec_end > data.len() {
                return Err(format!(
                    "{}: Section[{}] extends beyond file: offset=0x{:x}, size=0x{:x}, file_len=0x{:x}",
                    context, i, shdr.sh_offset, shdr.sh_size, data.len()
                ));
            }
        }
    }

    // 4. Validate dynamic section if present
    if let Some(ref dynamic) = elf.dynamic {
        // Must have DT_NULL terminator
        let has_null = dynamic
            .dyns
            .iter()
            .any(|d| d.d_tag == goblin::elf::dynamic::DT_NULL);
        if !has_null {
            return Err(format!("{context}: Dynamic section missing DT_NULL terminator"));
        }

        // DT_STRTAB should point to valid address
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == goblin::elf::dynamic::DT_STRTAB {
                // Should be within a loaded segment
                let addr = dyn_entry.d_val;
                let in_segment = elf.program_headers.iter().any(|p| {
                    p.p_type == PT_LOAD
                        && addr >= p.p_vaddr
                        && addr < p.p_vaddr + p.p_memsz
                });
                if !in_segment {
                    return Err(format!(
                        "{context}: DT_STRTAB 0x{addr:x} not in any PT_LOAD segment"
                    ));
                }
            }
        }
    }

    // 5. Validate interpreter if present
    if let Some(interp) = &elf.interpreter {
        if interp.is_empty() {
            return Err(format!("{context}: Empty interpreter path"));
        }
    }

    Ok(())
}

/// Verify binary is executable
fn verify_executable(data: &[u8]) -> Result<(), String> {
    let temp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let bin_path = temp_dir.path().join("test_bin");

    fs::write(&bin_path, data).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bin_path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin_path, perms).map_err(|e| e.to_string())?;
    }

    let output = Command::new(&bin_path).output().map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(format!("Execution failed: {:?}", output.status));
    }

    Ok(())
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_empty_rpath() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    writer.set_rpath("", false).unwrap();
    let output = writer.build().unwrap();

    validate_elf_comprehensive(&output, "empty_rpath").unwrap();
    verify_executable(&output).unwrap();
}

#[test]
fn test_single_char_rpath() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    writer.set_rpath("/", false).unwrap();
    let output = writer.build().unwrap();

    validate_elf_comprehensive(&output, "single_char_rpath").unwrap();
    verify_executable(&output).unwrap();
}

#[test]
fn test_very_long_rpath() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    // Create a very long rpath (4KB+)
    let long_path = (0..100)
        .map(|i| format!("/very/long/path/number/{i}/lib"))
        .collect::<Vec<_>>()
        .join(":");

    writer.set_rpath(&long_path, false).unwrap();
    let output = writer.build().unwrap();

    validate_elf_comprehensive(&output, "very_long_rpath").unwrap();
    verify_executable(&output).unwrap();

    // Verify the rpath was actually set
    let output_elf = Elf::parse(&output).unwrap();
    let has_runpath = output_elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns
                .iter()
                .any(|e| e.d_tag == goblin::elf::dynamic::DT_RUNPATH)
        })
        .unwrap_or(false);
    assert!(has_runpath, "RUNPATH should be set");
}

#[test]
fn test_special_characters_in_rpath() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    // Test with special characters (but valid path chars)
    let special_rpath = "/path/with spaces/and-dashes/and_underscores/and.dots";
    writer.set_rpath(special_rpath, false).unwrap();
    let output = writer.build().unwrap();

    validate_elf_comprehensive(&output, "special_chars_rpath").unwrap();
    verify_executable(&output).unwrap();
}

#[test]
fn test_origin_and_lib_variables() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    // Test with $ORIGIN and $LIB variables
    let rpath = "$ORIGIN/../lib:$ORIGIN/../lib64:$LIB";
    writer.set_rpath(rpath, false).unwrap();
    let output = writer.build().unwrap();

    validate_elf_comprehensive(&output, "origin_lib_rpath").unwrap();
    verify_executable(&output).unwrap();
}

#[test]
fn test_multiple_rpath_updates() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    // Perform multiple updates to the same binary
    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    writer.set_rpath("/first/path", false).unwrap();
    let output1 = writer.build().unwrap();

    validate_elf_comprehensive(&output1, "first_update").unwrap();

    // Now update the already-modified binary
    let elf2 = Elf::parse(&output1).unwrap();
    let mut writer2 = ElfWriter::new(&output1, &elf2).unwrap();

    writer2.set_rpath("/second/much/longer/path/that/requires/relocation", false).unwrap();
    let output2 = writer2.build().unwrap();

    validate_elf_comprehensive(&output2, "second_update").unwrap();
    verify_executable(&output2).unwrap();
}

#[test]
fn test_rpath_vs_runpath() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    // Test setting RPATH (force_rpath=true)
    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    writer.set_rpath("/test/rpath", true).unwrap(); // true = DT_RPATH
    let output = writer.build().unwrap();

    validate_elf_comprehensive(&output, "rpath_mode").unwrap();

    let output_elf = Elf::parse(&output).unwrap();
    let has_rpath = output_elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns
                .iter()
                .any(|e| e.d_tag == goblin::elf::dynamic::DT_RPATH)
        })
        .unwrap_or(false);
    assert!(has_rpath, "DT_RPATH should be set when force_rpath=true");
}

#[test]
fn test_remove_then_add_rpath() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    // First add a long rpath
    writer.set_rpath("/some/long/path/that/will/be/removed", false).unwrap();
    let output1 = writer.build().unwrap();

    // Now remove it
    let elf2 = Elf::parse(&output1).unwrap();
    let mut writer2 = ElfWriter::new(&output1, &elf2).unwrap();
    writer2.remove_rpath().unwrap();
    writer2.remove_runpath().unwrap();
    let output2 = writer2.build().unwrap();

    validate_elf_comprehensive(&output2, "after_remove").unwrap();

    // Add a new one
    let elf3 = Elf::parse(&output2).unwrap();
    let mut writer3 = ElfWriter::new(&output2, &elf3).unwrap();
    writer3.set_rpath("/new/path", false).unwrap();
    let output3 = writer3.build().unwrap();

    validate_elf_comprehensive(&output3, "after_re-add").unwrap();
    verify_executable(&output3).unwrap();
}

// ============================================================================
// Alignment Tests
// ============================================================================

#[test]
fn test_all_segments_properly_aligned() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    // Force section relocation with long rpath
    writer.set_rpath("/path/long/enough/to/force/section/relocation/behavior", false).unwrap();
    let output = writer.build().unwrap();

    let output_elf = Elf::parse(&output).unwrap();

    for (i, phdr) in output_elf.program_headers.iter().enumerate() {
        if phdr.p_type == PT_LOAD && phdr.p_align > 0 {
            // Check alignment invariant
            let diff = phdr.p_vaddr.wrapping_sub(phdr.p_offset);
            assert_eq!(
                diff % phdr.p_align,
                0,
                "PT_LOAD[{}] alignment invariant violated: (0x{:x} - 0x{:x}) % 0x{:x} != 0",
                i,
                phdr.p_vaddr,
                phdr.p_offset,
                phdr.p_align
            );

            // Alignment should be at least page size
            assert!(
                phdr.p_align >= 0x1000,
                "PT_LOAD[{}] alignment 0x{:x} < page size",
                i,
                phdr.p_align
            );
        }
    }
}

#[test]
fn test_section_alignment_preserved() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    writer.set_rpath("/path/to/trigger/relocation", false).unwrap();
    let output = writer.build().unwrap();

    let output_elf = Elf::parse(&output).unwrap();

    // Verify all sections with alignment > 1 are properly aligned
    for shdr in &output_elf.section_headers {
        if shdr.sh_addralign > 1 && shdr.sh_offset > 0 {
            assert_eq!(
                shdr.sh_offset % shdr.sh_addralign,
                0,
                "Section at offset 0x{:x} not aligned to {}",
                shdr.sh_offset,
                shdr.sh_addralign
            );
        }
    }
}

// ============================================================================
// Dynamic Section Integrity Tests
// ============================================================================

#[test]
fn test_dynamic_section_pointers_valid() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    writer.set_rpath("/path/to/trigger/relocation", false).unwrap();
    let output = writer.build().unwrap();

    let output_elf = Elf::parse(&output).unwrap();

    if let Some(dynamic) = &output_elf.dynamic {
        // Collect all PT_LOAD virtual address ranges
        let load_ranges: Vec<_> = output_elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| (p.p_vaddr, p.p_vaddr + p.p_memsz))
            .collect();

        // Check that address-type entries point to valid addresses
        for entry in &dynamic.dyns {
            let addr = entry.d_val;
            match entry.d_tag {
                goblin::elf::dynamic::DT_STRTAB
                | goblin::elf::dynamic::DT_SYMTAB
                | goblin::elf::dynamic::DT_HASH
                | goblin::elf::dynamic::DT_PLTGOT
                | goblin::elf::dynamic::DT_JMPREL
                | goblin::elf::dynamic::DT_REL
                | goblin::elf::dynamic::DT_RELA => {
                    if addr != 0 {
                        let in_load = load_ranges.iter().any(|(start, end)| addr >= *start && addr < *end);
                        assert!(
                            in_load,
                            "Dynamic entry tag 0x{:x} points to invalid address 0x{:x}",
                            entry.d_tag, addr
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

#[test]
fn test_dynstr_accessible() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    let test_rpath = "/my/custom/rpath/value";
    writer.set_rpath(test_rpath, false).unwrap();
    let output = writer.build().unwrap();

    let output_elf = Elf::parse(&output).unwrap();

    // The runpath should be readable from dynstrtab
    if let Some(dynamic) = &output_elf.dynamic {
        let runpath_entry = dynamic
            .dyns
            .iter()
            .find(|e| e.d_tag == goblin::elf::dynamic::DT_RUNPATH);

        if let Some(entry) = runpath_entry {
            let runpath = output_elf
                .dynstrtab
                .get_at(entry.d_val as usize)
                .expect("Failed to read RUNPATH from dynstrtab");
            assert_eq!(runpath, test_rpath, "RUNPATH value mismatch");
        } else {
            panic!("RUNPATH entry not found in dynamic section");
        }
    }
}

// ============================================================================
// Idempotency Tests
// ============================================================================

#[test]
fn test_setting_same_rpath_twice() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let rpath = "/consistent/path";

    // First modification
    let elf1 = Elf::parse(&data).unwrap();
    let mut writer1 = ElfWriter::new(&data, &elf1).unwrap();
    writer1.set_rpath(rpath, false).unwrap();
    let output1 = writer1.build().unwrap();

    // Second modification with same rpath
    let elf2 = Elf::parse(&output1).unwrap();
    let mut writer2 = ElfWriter::new(&output1, &elf2).unwrap();
    writer2.set_rpath(rpath, false).unwrap();
    let output2 = writer2.build().unwrap();

    // Both should be valid and executable
    validate_elf_comprehensive(&output1, "first_set").unwrap();
    validate_elf_comprehensive(&output2, "second_set").unwrap();
    verify_executable(&output2).unwrap();
}

// ============================================================================
// Regression Tests
// ============================================================================

#[test]
fn test_pt_interp_updated_correctly() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let elf = Elf::parse(&data).unwrap();
    let mut writer = ElfWriter::new(&data, &elf).unwrap();

    // Force relocation which should also relocate .interp
    writer.set_rpath("/very/long/path/to/force/section/relocation", false).unwrap();
    let output = writer.build().unwrap();

    let output_elf = Elf::parse(&output).unwrap();

    // Find PT_INTERP segment
    let interp_phdr = output_elf
        .program_headers
        .iter()
        .find(|p| p.p_type == goblin::elf::program_header::PT_INTERP);

    if let Some(phdr) = interp_phdr {
        // Read the interpreter path from the file at the segment offset
        let start = phdr.p_offset as usize;
        let end = start + phdr.p_filesz as usize;

        if end <= output.len() {
            let interp_bytes = &output[start..end];
            // Should be null-terminated string
            let interp = std::str::from_utf8(interp_bytes)
                .expect("Interpreter path should be valid UTF-8")
                .trim_end_matches('\0');

            assert!(
                interp.starts_with("/lib") || interp.starts_with("/usr"),
                "Interpreter path looks corrupted: {interp:?}"
            );
        }
    }

    // Also verify via goblin's interpreter parsing
    assert!(
        output_elf.interpreter.is_some(),
        "Interpreter should be parseable"
    );
    let interp = output_elf.interpreter.as_ref().unwrap();
    assert!(
        interp.contains("ld-linux"),
        "Interpreter should be Linux dynamic linker: {interp}"
    );
}

#[test]
fn test_note_sections_preserved() {
    let Some(data) = get_test_binary() else {
        eprintln!("Skipping: test binary not found");
        return;
    };

    let original_elf = Elf::parse(&data).unwrap();
    let original_note_count = original_elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_NOTE)
        .count();

    let mut writer = ElfWriter::new(&data, &original_elf).unwrap();
    writer.set_rpath("/path/to/trigger/relocation", false).unwrap();
    let output = writer.build().unwrap();

    let output_elf = Elf::parse(&output).unwrap();
    let output_note_count = output_elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_NOTE)
        .count();

    // Should have at least as many NOTE segments (may have more due to normalization)
    assert!(
        output_note_count >= original_note_count,
        "Lost NOTE segments: had {original_note_count}, now have {output_note_count}"
    );
}
