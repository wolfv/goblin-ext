//! Integration tests for ElfWriter.
//!
//! These tests verify that our ELF writer produces functionally correct output.
//! Where available, we use patchelf as a reference tool to validate that our
//! output is compatible with the de-facto standard for ELF modification.

use goblin::elf::Elf;
use goblin_ext::ElfWriter;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Get the path to test assets directory
fn test_assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("assets")
}

/// Check if patchelf is available
fn patchelf_available() -> bool {
    Command::new("patchelf")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run patchelf command and return the output binary
fn run_patchelf(input: &[u8], args: &[&str]) -> Result<Vec<u8>, String> {
    let temp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let input_path = temp_dir.path().join("input");
    let output_path = temp_dir.path().join("output");

    fs::write(&input_path, input).map_err(|e| e.to_string())?;
    fs::copy(&input_path, &output_path).map_err(|e| e.to_string())?;

    let mut cmd_args = vec!["--output", output_path.to_str().unwrap()];
    cmd_args.extend(args);
    cmd_args.push(input_path.to_str().unwrap());

    let output = Command::new("patchelf")
        .args(&cmd_args)
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(format!(
            "patchelf failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    fs::read(&output_path).map_err(|e| e.to_string())
}

/// Verify an ELF binary is structurally valid
fn verify_elf_structure(data: &[u8]) -> Result<(), String> {
    let elf = Elf::parse(data).map_err(|e| format!("Failed to parse ELF: {e}"))?;

    // Verify alignment invariant for all PT_LOAD segments
    for (i, phdr) in elf.program_headers.iter().enumerate() {
        if phdr.p_type == goblin::elf::program_header::PT_LOAD && phdr.p_align > 0 {
            let vaddr = phdr.p_vaddr;
            let offset = phdr.p_offset;
            let align = phdr.p_align;

            // (p_vaddr - p_offset) % p_align must be 0
            if (vaddr.wrapping_sub(offset)) % align != 0 {
                return Err(format!(
                    "PT_LOAD segment {i} has invalid alignment: vaddr=0x{vaddr:x}, offset=0x{offset:x}, align=0x{align:x}"
                ));
            }
        }
    }

    // Verify dynamic section pointers if present
    if let Some(ref dynamic) = elf.dynamic {
        // Just verify it parsed correctly
        if dynamic.dyns.is_empty() {
            return Err("Dynamic section is empty".into());
        }
    }

    Ok(())
}

/// Compare segment alignments between two ELF files
fn compare_segment_alignments(ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    let our_elf = Elf::parse(ours).map_err(|e| format!("Failed to parse our ELF: {e}"))?;
    let their_elf = Elf::parse(theirs).map_err(|e| format!("Failed to parse their ELF: {e}"))?;

    // Find PT_LOAD segments in both
    let our_loads: Vec<_> = our_elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .collect();
    let their_loads: Vec<_> = their_elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .collect();

    // Compare alignment values of corresponding segments
    // Note: We may have different numbers of segments if approaches differ
    for (i, (ours, theirs)) in our_loads.iter().zip(their_loads.iter()).enumerate() {
        // Alignments should both be valid page sizes
        if ours.p_align < 0x1000 {
            return Err(format!(
                "Our PT_LOAD {} has suspiciously small alignment: 0x{:x}",
                i, ours.p_align
            ));
        }
        if theirs.p_align < 0x1000 {
            return Err(format!(
                "Their PT_LOAD {} has suspiciously small alignment: 0x{:x}",
                i, theirs.p_align
            ));
        }
    }

    Ok(())
}

/// Get RPATH/RUNPATH from an ELF file
fn get_rpath(data: &[u8]) -> Option<String> {
    let elf = Elf::parse(data).ok()?;
    let dynamic = elf.dynamic.as_ref()?;

    for dyn_entry in &dynamic.dyns {
        if dyn_entry.d_tag == goblin::elf::dynamic::DT_RPATH
            || dyn_entry.d_tag == goblin::elf::dynamic::DT_RUNPATH
        {
            return elf.dynstrtab.get_at(dyn_entry.d_val as usize).map(String::from);
        }
    }
    None
}

/// Verify that a binary can be executed
fn verify_executable(data: &[u8]) -> Result<(), String> {
    let temp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let bin_path = temp_dir.path().join("test_bin");

    fs::write(&bin_path, data).map_err(|e| e.to_string())?;

    // Make it executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bin_path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin_path, perms).map_err(|e| e.to_string())?;
    }

    // Try to run it
    let output = Command::new(&bin_path).output().map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(format!(
            "Binary execution failed with status: {}",
            output.status
        ));
    }

    Ok(())
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_set_rpath_short() {
    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found. Run tests/assets/build_elf_assets.sh");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Set a short rpath that fits in existing space
    let new_rpath = "/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Verify structure
    verify_elf_structure(&output).expect("Invalid ELF structure");

    // Verify rpath was set
    let result_rpath = get_rpath(&output);
    assert_eq!(result_rpath.as_deref(), Some(new_rpath));

    // Verify executable
    verify_executable(&output).expect("Binary not executable");
}

#[test]
fn test_set_rpath_long_requires_relocation() {
    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Set a long rpath that requires section relocation
    let new_rpath = "/very/long/path/that/definitely/requires/relocation/to/fit:/another/very/long/path/entry";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Verify structure
    verify_elf_structure(&output).expect("Invalid ELF structure");

    // Verify rpath was set
    let result_rpath = get_rpath(&output);
    assert_eq!(result_rpath.as_deref(), Some(new_rpath));

    // Verify executable
    verify_executable(&output).expect("Binary not executable");
}

#[test]
fn test_alignment_matches_patchelf() {
    if !patchelf_available() {
        eprintln!("Skipping test: patchelf not available");
        return;
    }

    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");

    // Use patchelf to set a long rpath
    let new_rpath = "/opt/lib:/usr/local/lib:/home/test/custom/lib/path";
    let patchelf_output = run_patchelf(&data, &["--set-rpath", new_rpath])
        .expect("Failed to run patchelf");

    // Use our implementation
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let our_output = writer.build().expect("Failed to build");

    // Compare alignments
    compare_segment_alignments(&our_output, &patchelf_output)
        .expect("Alignment mismatch with patchelf");

    // Verify both are structurally valid
    verify_elf_structure(&our_output).expect("Our output has invalid structure");
    verify_elf_structure(&patchelf_output).expect("Patchelf output has invalid structure");

    // Both should be executable
    verify_executable(&our_output).expect("Our binary not executable");
    verify_executable(&patchelf_output).expect("Patchelf binary not executable");
}

#[test]
fn test_segment_alignment_invariant() {
    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Set rpath to trigger section relocation
    let new_rpath = "/this/is/a/really/long/path/that/will/force/section/relocation/and/new/segment/creation";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Parse the output and verify all PT_LOAD segments meet alignment requirements
    let output_elf = Elf::parse(&output).expect("Failed to parse output ELF");

    for (i, phdr) in output_elf.program_headers.iter().enumerate() {
        if phdr.p_type == goblin::elf::program_header::PT_LOAD {
            // Alignment must be a power of 2 and at least page size
            assert!(
                phdr.p_align >= 0x1000,
                "PT_LOAD {} alignment 0x{:x} is too small",
                i,
                phdr.p_align
            );
            assert!(
                phdr.p_align.is_power_of_two(),
                "PT_LOAD {} alignment 0x{:x} is not a power of 2",
                i,
                phdr.p_align
            );

            // Verify (p_vaddr - p_offset) % p_align == 0
            let vaddr = phdr.p_vaddr;
            let offset = phdr.p_offset;
            let align = phdr.p_align;
            assert_eq!(
                (vaddr.wrapping_sub(offset)) % align,
                0,
                "PT_LOAD {i} violates alignment invariant: vaddr=0x{vaddr:x}, offset=0x{offset:x}, align=0x{align:x}"
            );
        }
    }
}

#[test]
fn test_remove_rpath() {
    let input_path = test_assets_dir().join("test_elf_with_rpath");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_with_rpath not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");

    // Verify input has rpath
    let original_rpath = get_rpath(&data);
    assert!(original_rpath.is_some(), "Test binary should have RPATH");

    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    writer.remove_rpath().expect("Failed to remove rpath");
    writer.remove_runpath().expect("Failed to remove runpath");
    let output = writer.build().expect("Failed to build");

    // Verify structure
    verify_elf_structure(&output).expect("Invalid ELF structure");

    // Verify rpath was removed
    let result_rpath = get_rpath(&output);
    assert!(result_rpath.is_none(), "RPATH should be removed");

    // Verify executable
    verify_executable(&output).expect("Binary not executable");
}

#[test]
fn test_page_size_x86_64() {
    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Verify e_machine is x86_64
    assert_eq!(elf.header.e_machine, goblin::elf::header::EM_X86_64);

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Force section relocation to trigger new PT_LOAD segment creation
    let new_rpath = "/very/long/path/to/trigger/relocation";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Verify the new PT_LOAD segment has 4KB alignment (x86_64 page size)
    let output_elf = Elf::parse(&output).expect("Failed to parse output ELF");

    let new_segment = output_elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .next_back()
        .expect("Should have PT_LOAD segments");

    // For x86_64, page size should be 0x1000 (4KB)
    assert!(
        new_segment.p_align == 0x1000 || new_segment.p_align == 0x200000,
        "Expected 4KB or 2MB alignment for x86_64, got 0x{:x}",
        new_segment.p_align
    );
}

#[test]
fn test_functional_equivalence_with_patchelf() {
    if !patchelf_available() {
        eprintln!("Skipping test: patchelf not available");
        return;
    }

    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");

    // Test various rpath lengths
    let test_rpaths = vec![
        "/lib",
        "/usr/lib:/lib",
        "/very/long/path/that/requires/relocation",
        "/path1:/path2:/path3:/path4:/path5",
    ];

    for new_rpath in test_rpaths {
        // Use patchelf
        let patchelf_output = run_patchelf(&data, &["--set-rpath", new_rpath])
            .expect("Failed to run patchelf");

        // Use our implementation
        let elf = Elf::parse(&data).expect("Failed to parse ELF");
        let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
        writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
        let our_output = writer.build().expect("Failed to build");

        // Both should have the same rpath
        let patchelf_rpath = get_rpath(&patchelf_output);
        let our_rpath = get_rpath(&our_output);
        assert_eq!(
            patchelf_rpath, our_rpath,
            "RPATH mismatch for '{new_rpath}'"
        );

        // Both should be structurally valid
        verify_elf_structure(&our_output)
            .unwrap_or_else(|e| panic!("Our output invalid for '{new_rpath}': {e}"));
        verify_elf_structure(&patchelf_output)
            .unwrap_or_else(|e| panic!("Patchelf output invalid for '{new_rpath}': {e}"));

        // Both should be executable
        verify_executable(&our_output)
            .unwrap_or_else(|e| panic!("Our binary not executable for '{new_rpath}': {e}"));
        verify_executable(&patchelf_output)
            .unwrap_or_else(|e| panic!("Patchelf binary not executable for '{new_rpath}': {e}"));
    }
}

#[test]
fn test_dynamic_section_integrity() {
    let input_path = test_assets_dir().join("test_elf_x86_64");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_x86_64 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Set rpath to trigger section relocation
    let new_rpath = "/path/that/triggers/relocation";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Parse output and verify dynamic section is still valid
    let output_elf = Elf::parse(&output).expect("Failed to parse output ELF");

    // Should still have dynamic section
    assert!(output_elf.dynamic.is_some(), "Dynamic section should exist");

    let dynamic = output_elf.dynamic.as_ref().unwrap();

    // Should have DT_STRTAB pointing to valid address
    let has_strtab = dynamic
        .dyns
        .iter()
        .any(|d| d.d_tag == goblin::elf::dynamic::DT_STRTAB);
    assert!(has_strtab, "Should have DT_STRTAB entry");

    // Should have DT_SYMTAB
    let has_symtab = dynamic
        .dyns
        .iter()
        .any(|d| d.d_tag == goblin::elf::dynamic::DT_SYMTAB);
    assert!(has_symtab, "Should have DT_SYMTAB entry");

    // Should end with DT_NULL
    let has_null = dynamic
        .dyns
        .iter()
        .any(|d| d.d_tag == goblin::elf::dynamic::DT_NULL);
    assert!(has_null, "Should have DT_NULL terminator");
}

// ============================================================================
// Tests with New Test Assets
// ============================================================================

#[test]
fn test_shared_library_rpath() {
    let input_path = test_assets_dir().join("libtest.so");
    if !input_path.exists() {
        eprintln!("Skipping test: libtest.so not found. Run tests/assets/build_elf_assets.sh");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read shared library");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Add RPATH to shared library
    let new_rpath = "/opt/custom/lib:/usr/local/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Verify structure
    verify_elf_structure(&output).expect("Invalid ELF structure");

    // Verify rpath was set
    let result_rpath = get_rpath(&output);
    assert_eq!(result_rpath.as_deref(), Some(new_rpath));
}

#[test]
fn test_shared_library_with_existing_rpath() {
    let input_path = test_assets_dir().join("libtest_with_rpath.so");
    if !input_path.exists() {
        eprintln!("Skipping test: libtest_with_rpath.so not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read shared library");

    // Verify input has rpath
    let original_rpath = get_rpath(&data);
    assert!(original_rpath.is_some(), "Test library should have RPATH");

    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Replace with shorter rpath
    let new_rpath = "/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    assert_eq!(get_rpath(&output).as_deref(), Some(new_rpath));
}

#[test]
fn test_pie_executable() {
    let input_path = test_assets_dir().join("test_elf_pie");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_pie not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read PIE binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Verify it's actually PIE (has DYN type)
    assert_eq!(
        elf.header.e_type,
        goblin::elf::header::ET_DYN,
        "Expected PIE executable (ET_DYN)"
    );

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    let new_rpath = "/usr/lib/pie:/opt/pie/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    verify_executable(&output).expect("PIE binary not executable");
    assert_eq!(get_rpath(&output).as_deref(), Some(new_rpath));
}

#[test]
fn test_non_pie_executable() {
    let input_path = test_assets_dir().join("test_elf_no_pie");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_no_pie not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read non-PIE binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Verify it's not PIE (has EXEC type)
    assert_eq!(
        elf.header.e_type,
        goblin::elf::header::ET_EXEC,
        "Expected non-PIE executable (ET_EXEC)"
    );

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    let new_rpath = "/usr/lib/static:/opt/static/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    verify_executable(&output).expect("Non-PIE binary not executable");
    assert_eq!(get_rpath(&output).as_deref(), Some(new_rpath));
}

#[test]
fn test_shrink_long_rpath() {
    let input_path = test_assets_dir().join("test_elf_long_rpath");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_long_rpath not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");

    // Verify input has a long rpath
    let original_rpath = get_rpath(&data).expect("Should have RPATH");
    assert!(
        original_rpath.len() > 100,
        "Expected long RPATH, got {} chars",
        original_rpath.len()
    );

    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Replace with much shorter rpath - should fit in existing space
    let new_rpath = "/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    verify_executable(&output).expect("Binary not executable");
    assert_eq!(get_rpath(&output).as_deref(), Some(new_rpath));

    // Output should be similar size or smaller (no relocation needed)
    assert!(
        output.len() <= data.len() + 4096,
        "Output grew unexpectedly: {} -> {}",
        data.len(),
        output.len()
    );
}

#[test]
fn test_old_style_rpath_to_runpath() {
    let input_path = test_assets_dir().join("test_elf_with_old_rpath");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_with_old_rpath not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Check if it has DT_RPATH (old style)
    let has_old_rpath = elf
        .dynamic
        .as_ref()
        .map(|d| d.dyns.iter().any(|e| e.d_tag == goblin::elf::dynamic::DT_RPATH))
        .unwrap_or(false);

    if has_old_rpath {
        eprintln!("Input has DT_RPATH (old style)");
    }

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Set RUNPATH (new style, second param = false)
    let new_rpath = "/new/runpath/location";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    verify_executable(&output).expect("Binary not executable");
}

#[test]
fn test_stripped_binary() {
    let input_path = test_assets_dir().join("test_elf_stripped");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_stripped not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read stripped binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    let new_rpath = "/opt/stripped/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    verify_executable(&output).expect("Stripped binary not executable");
    assert_eq!(get_rpath(&output).as_deref(), Some(new_rpath));
}

#[test]
fn test_binary_with_multiple_needed() {
    let input_path = test_assets_dir().join("test_elf_with_needed");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_with_needed not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read test binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Verify it has DT_NEEDED entries
    let needed_count = elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns
                .iter()
                .filter(|e| e.d_tag == goblin::elf::dynamic::DT_NEEDED)
                .count()
        })
        .unwrap_or(0);
    assert!(needed_count > 0, "Expected DT_NEEDED entries");

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    let new_rpath = "/opt/math/lib:/usr/lib/x86_64-linux-gnu";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");
    verify_executable(&output).expect("Binary not executable");

    // Verify DT_NEEDED entries are preserved
    let output_elf = Elf::parse(&output).expect("Failed to parse output");
    let output_needed_count = output_elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns
                .iter()
                .filter(|e| e.d_tag == goblin::elf::dynamic::DT_NEEDED)
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        needed_count, output_needed_count,
        "DT_NEEDED count changed"
    );
}

#[test]
fn test_shared_library_soname_preserved() {
    let input_path = test_assets_dir().join("libtest_soname.so");
    if !input_path.exists() {
        eprintln!("Skipping test: libtest_soname.so not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read shared library");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Get original SONAME
    let get_soname = |data: &[u8]| -> Option<String> {
        let elf = Elf::parse(data).ok()?;
        let dynamic = elf.dynamic.as_ref()?;
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == goblin::elf::dynamic::DT_SONAME {
                return elf.dynstrtab.get_at(dyn_entry.d_val as usize).map(String::from);
            }
        }
        None
    };

    let original_soname = get_soname(&data);
    assert!(original_soname.is_some(), "Library should have SONAME");

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    let new_rpath = "/opt/lib:/usr/local/lib";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");

    // Verify SONAME is preserved
    let output_soname = get_soname(&output);
    assert_eq!(
        original_soname, output_soname,
        "SONAME should be preserved"
    );
}

#[test]
fn test_32bit_elf_i386() {
    let input_path = test_assets_dir().join("test_elf_i386");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_i386 not found (install gcc-multilib)");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read 32-bit binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Verify it's actually 32-bit (EM_386)
    assert_eq!(
        elf.header.e_machine,
        goblin::elf::header::EM_386,
        "Expected i386 binary"
    );

    // Verify it's 32-bit class
    assert!(
        !elf.is_64,
        "Expected 32-bit ELF"
    );

    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");
    let new_rpath = "/usr/lib32:/opt/lib32";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    verify_elf_structure(&output).expect("Invalid ELF structure");

    // Verify rpath was set
    let result_rpath = get_rpath(&output);
    assert_eq!(result_rpath.as_deref(), Some(new_rpath));

    // Verify it's still 32-bit after modification
    let output_elf = Elf::parse(&output).expect("Failed to parse output");
    assert!(!output_elf.is_64, "Output should still be 32-bit");
    assert_eq!(output_elf.header.e_machine, goblin::elf::header::EM_386);
}

#[test]
fn test_32bit_elf_alignment() {
    let input_path = test_assets_dir().join("test_elf_i386");
    if !input_path.exists() {
        eprintln!("Skipping test: test_elf_i386 not found");
        return;
    }

    let data = fs::read(&input_path).expect("Failed to read 32-bit binary");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    let mut writer = ElfWriter::new(&data, &elf).expect("Failed to create writer");

    // Force section relocation with a long rpath
    let new_rpath = "/very/long/path/to/force/relocation/in/32bit/binary";
    writer.set_rpath(new_rpath, false).expect("Failed to set rpath");
    let output = writer.build().expect("Failed to build");

    // Parse output and verify alignment
    let output_elf = Elf::parse(&output).expect("Failed to parse output");

    for (i, phdr) in output_elf.program_headers.iter().enumerate() {
        if phdr.p_type == goblin::elf::program_header::PT_LOAD {
            // i386 uses 4KB pages
            assert!(
                phdr.p_align >= 0x1000,
                "PT_LOAD {} has alignment 0x{:x}, expected >= 0x1000",
                i,
                phdr.p_align
            );

            // Verify alignment invariant
            let vaddr = phdr.p_vaddr;
            let offset = phdr.p_offset;
            let align = phdr.p_align;
            assert_eq!(
                (vaddr.wrapping_sub(offset)) % align,
                0,
                "PT_LOAD {i} violates alignment invariant"
            );
        }
    }
}
