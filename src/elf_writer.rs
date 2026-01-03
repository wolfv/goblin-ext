//! ELF file writing and modification support.
//!
//! This module provides functionality for writing and modifying ELF files,
//! including support for changing dynamic section entries like RPATH/RUNPATH.
//!
//! The writer supports automatic section relocation when string tables need to grow,
//! allowing unlimited RPATH/RUNPATH modifications.

use alloc::vec::Vec;
use goblin::container::Ctx;
use goblin::elf::dynamic::Dyn;
use goblin::elf::header::Header;
use goblin::elf::program_header::ProgramHeader;
use goblin::elf::section_header::SectionHeader;
use goblin::error;
use scroll::{ctx::SizeWith, ctx::TryIntoCtx};

/// A builder for modifying and writing ELF files.
///
/// This struct allows you to load an existing ELF file, modify various
/// components (like dynamic section entries), and write it back out.
#[derive(Debug)]
pub struct ElfWriter<'a> {
    /// Original binary data
    data: &'a [u8],
    /// ELF header
    header: Header,
    /// Program headers
    program_headers: Vec<ProgramHeader>,
    /// Section headers
    section_headers: Vec<SectionHeader>,
    /// Dynamic section entries (if present)
    dynamic_entries: Option<Vec<Dyn>>,
    /// Original number of dynamic entries
    original_dynamic_count: usize,
    /// Modified dynamic string table
    dynstrtab: Vec<u8>,
    /// Original dynamic string table offset
    dynstrtab_offset: usize,
    /// Original dynamic string table size
    dynstrtab_size: usize,
    /// Context (endianness, container size)
    ctx: Ctx,
}

impl<'a> ElfWriter<'a> {
    /// Create a new ElfWriter from an existing ELF binary.
    ///
    /// # Arguments
    ///
    /// * `data` - The original ELF binary data
    /// * `elf` - Parsed ELF structure
    ///
    /// # Example
    ///
    /// ```no_run
    /// use goblin::elf::Elf;
    /// use goblin_ext::ElfWriter;
    ///
    /// let data = std::fs::read("binary").unwrap();
    /// let elf = Elf::parse(&data).unwrap();
    /// let writer = ElfWriter::new(&data, &elf).unwrap();
    /// ```
    pub fn new(data: &'a [u8], elf: &goblin::elf::Elf) -> error::Result<Self> {
        let mut dynstrtab = Vec::new();
        let mut dynstrtab_offset = 0;
        let mut dynstrtab_size = 0;

        // Copy the dynamic string table if it exists
        if let Some(ref dynamic) = elf.dynamic {
            dynstrtab_offset = dynamic.info.strtab;
            dynstrtab_size = dynamic.info.strsz;
            if dynstrtab_offset + dynstrtab_size <= data.len() {
                dynstrtab
                    .extend_from_slice(&data[dynstrtab_offset..dynstrtab_offset + dynstrtab_size]);
            }
        }

        let dynamic_entries = elf.dynamic.as_ref().map(|d| d.dyns.clone());
        let original_dynamic_count = elf.dynamic.as_ref().map_or(0, |d| d.dyns.len());

        // Construct Ctx from public fields
        let container = if elf.is_64 {
            goblin::container::Container::Big
        } else {
            goblin::container::Container::Little
        };
        let le = if elf.little_endian {
            scroll::Endian::Little
        } else {
            scroll::Endian::Big
        };
        let ctx = Ctx::new(container, le);

        Ok(ElfWriter {
            data,
            header: elf.header,
            program_headers: elf.program_headers.clone(),
            section_headers: elf.section_headers.clone(),
            dynamic_entries,
            original_dynamic_count,
            dynstrtab,
            dynstrtab_offset,
            dynstrtab_size,
            ctx,
        })
    }

    /// Set the RPATH/RUNPATH for this ELF binary (matching patchelf --set-rpath behavior).
    ///
    /// This method mimics the behavior of patchelf --set-rpath:
    /// - If DT_RUNPATH exists, it modifies that entry
    /// - If only DT_RPATH exists (and force_rpath is false), it converts to DT_RUNPATH
    /// - If neither exists, it creates a DT_RUNPATH entry
    /// - Old string values are overwritten with 'X' characters (for security)
    ///
    /// # Arguments
    ///
    /// * `rpath` - The new RPATH value (e.g., "/usr/local/lib:/opt/lib")
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use goblin::elf::Elf;
    /// # use goblin_ext::ElfWriter;
    /// # let data = vec![0u8; 100];
    /// # let elf = Elf::parse(&data).unwrap();
    /// let mut writer = ElfWriter::new(&data, &elf).unwrap();
    /// writer.set_rpath("/usr/local/lib").unwrap();
    /// ```
    pub fn set_rpath(&mut self, rpath: &str) -> error::Result<()> {
        self.modify_rpath(rpath, false)
    }

    /// Set the RUNPATH for this ELF binary.
    ///
    /// This will modify or add a DT_RUNPATH entry in the dynamic section.
    /// RUNPATH is the modern replacement for RPATH.
    ///
    /// # Arguments
    ///
    /// * `runpath` - The new RUNPATH value (e.g., "/usr/local/lib:/opt/lib")
    pub fn set_runpath(&mut self, runpath: &str) -> error::Result<()> {
        self.modify_rpath(runpath, false)
    }

    /// Set the RPATH for this ELF binary, forcing DT_RPATH instead of DT_RUNPATH.
    ///
    /// This matches patchelf --set-rpath --force-rpath behavior.
    pub fn set_rpath_forced(&mut self, rpath: &str) -> error::Result<()> {
        self.modify_rpath(rpath, true)
    }

    /// Modify RPATH/RUNPATH entry (internal implementation matching patchelf behavior).
    ///
    /// This implements the core logic matching patchelf's modifyRPath function:
    /// - Without force_rpath: prefer DT_RUNPATH, convert DT_RPATH to DT_RUNPATH
    /// - With force_rpath: prefer DT_RPATH, convert DT_RUNPATH to DT_RPATH
    /// - Overwrites old string with 'X' characters
    fn modify_rpath(&mut self, new_rpath: &str, force_rpath: bool) -> error::Result<()> {
        let entries = self
            .dynamic_entries
            .as_ref()
            .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

        // Find existing DT_RPATH and DT_RUNPATH entries
        let rpath_entry = entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.d_tag == goblin::elf::dynamic::DT_RPATH);
        let runpath_entry = entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.d_tag == goblin::elf::dynamic::DT_RUNPATH);

        let (entry_idx, old_offset, needs_tag_change) =
            match (rpath_entry, runpath_entry, force_rpath) {
                // DT_RUNPATH exists - use it
                (_, Some((idx, entry)), false) => (Some(idx), Some(entry.d_val as usize), false),
                // Only DT_RPATH exists and not forcing - convert to RUNPATH
                (Some((idx, entry)), None, false) => (Some(idx), Some(entry.d_val as usize), true),
                // DT_RPATH exists and forcing - use it
                (Some((idx, entry)), _, true) => (Some(idx), Some(entry.d_val as usize), false),
                // Only DT_RUNPATH exists and forcing - convert to RPATH
                (None, Some((idx, entry)), true) => (Some(idx), Some(entry.d_val as usize), true),
                // Neither exists - will add new entry
                (None, None, _) => (None, None, false),
            };

        // Calculate new string offset
        let str_offset = if let Some(offset) = old_offset {
            let old_len = self.get_string_length_at(offset);
            let new_len = new_rpath.len() + 1; // +1 for null terminator

            if new_len <= old_len {
                // Overwrite old string with 'X' characters first (patchelf behavior)
                self.taint_string_at(offset, old_len);
                // Then write the new string
                self.replace_string_at(offset, new_rpath, old_len)?;
                offset
            } else {
                // Taint old string even when appending new one
                self.taint_string_at(offset, old_len);
                // Need more space, append to the end
                self.add_to_dynstrtab(new_rpath)
            }
        } else {
            // New entry, append to the end
            self.add_to_dynstrtab(new_rpath)
        };

        // Now update or add the entry
        let entries = self
            .dynamic_entries
            .as_mut()
            .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

        let target_tag = if force_rpath {
            goblin::elf::dynamic::DT_RPATH
        } else {
            goblin::elf::dynamic::DT_RUNPATH
        };

        if let Some(idx) = entry_idx {
            // Update existing entry
            entries[idx].d_val = str_offset as u64;
            if needs_tag_change {
                entries[idx].d_tag = target_tag;
            }
        } else {
            // Add new entry before DT_NULL
            let null_pos = entries
                .iter()
                .position(|e| e.d_tag == goblin::elf::dynamic::DT_NULL);
            let new_entry = Dyn {
                d_tag: target_tag,
                d_val: str_offset as u64,
            };

            if let Some(pos) = null_pos {
                entries.insert(pos, new_entry);
            } else {
                entries.push(new_entry);
            }
        }

        Ok(())
    }

    /// Taint a string with 'X' characters (patchelf behavior for security).
    fn taint_string_at(&mut self, offset: usize, len: usize) {
        // Fill the string (excluding null terminator) with 'X' characters
        let end = (offset + len - 1).min(self.dynstrtab.len());
        for i in offset..end {
            self.dynstrtab[i] = b'X';
        }
    }

    /// Set the SONAME for this ELF shared library.
    ///
    /// # Arguments
    ///
    /// * `soname` - The new SONAME value (e.g., "libfoo.so.1")
    pub fn set_soname(&mut self, soname: &str) -> error::Result<()> {
        self.set_dynamic_string_entry(goblin::elf::dynamic::DT_SONAME, soname)
    }

    /// Remove RPATH entry from the dynamic section.
    pub fn remove_rpath(&mut self) -> error::Result<()> {
        self.remove_dynamic_entry(goblin::elf::dynamic::DT_RPATH)
    }

    /// Remove RUNPATH entry from the dynamic section.
    pub fn remove_runpath(&mut self) -> error::Result<()> {
        self.remove_dynamic_entry(goblin::elf::dynamic::DT_RUNPATH)
    }

    /// Convert DT_RPATH to DT_RUNPATH.
    pub fn rpath_to_runpath(&mut self) -> error::Result<()> {
        if let Some(ref mut entries) = self.dynamic_entries {
            for entry in entries.iter_mut() {
                if entry.d_tag == goblin::elf::dynamic::DT_RPATH {
                    entry.d_tag = goblin::elf::dynamic::DT_RUNPATH;
                }
            }
        }
        Ok(())
    }

    /// Convert DT_RUNPATH to DT_RPATH.
    pub fn runpath_to_rpath(&mut self) -> error::Result<()> {
        if let Some(ref mut entries) = self.dynamic_entries {
            for entry in entries.iter_mut() {
                if entry.d_tag == goblin::elf::dynamic::DT_RUNPATH {
                    entry.d_tag = goblin::elf::dynamic::DT_RPATH;
                }
            }
        }
        Ok(())
    }

    /// Set a dynamic section string entry (RPATH, RUNPATH, SONAME, etc.).
    fn set_dynamic_string_entry(&mut self, tag: u64, value: &str) -> error::Result<()> {
        // First, find existing offset without holding a borrow
        let existing_offset = if let Some(ref entries) = self.dynamic_entries {
            entries
                .iter()
                .find(|e| e.d_tag == tag)
                .map(|e| e.d_val as usize)
        } else {
            return Err(error::Error::Malformed("No dynamic section found".into()));
        };

        // Try to reuse existing space if possible
        let str_offset = if let Some(offset) = existing_offset {
            // Calculate available space at the existing offset
            let old_len = self.get_string_length_at(offset);
            let new_len = value.len() + 1; // +1 for null terminator

            if new_len <= old_len {
                // We can reuse the space
                self.replace_string_at(offset, value, old_len)?;
                offset
            } else {
                // Need more space, append to the end
                self.add_to_dynstrtab(value)
            }
        } else {
            // New entry, append to the end
            self.add_to_dynstrtab(value)
        };

        // Now update or add the entry with a mutable borrow
        let entries = self
            .dynamic_entries
            .as_mut()
            .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

        let mut found = false;
        for entry in entries.iter_mut() {
            if entry.d_tag == tag {
                entry.d_val = str_offset as u64;
                found = true;
                break;
            }
        }

        if !found {
            // Add before DT_NULL
            let null_pos = entries
                .iter()
                .position(|e| e.d_tag == goblin::elf::dynamic::DT_NULL);
            let new_entry = Dyn {
                d_tag: tag,
                d_val: str_offset as u64,
            };

            if let Some(pos) = null_pos {
                entries.insert(pos, new_entry);
            } else {
                entries.push(new_entry);
            }
        }

        Ok(())
    }

    /// Get the length of a null-terminated string at the given offset in dynstrtab.
    fn get_string_length_at(&self, offset: usize) -> usize {
        let start = offset;
        let mut end = offset;
        while end < self.dynstrtab.len() && self.dynstrtab[end] != 0 {
            end += 1;
        }
        end - start + 1 // Include null terminator
    }

    /// Replace a string at a specific offset.
    /// Note: Does NOT pad extra space - patchelf leaves 'X' characters after the new string.
    fn replace_string_at(
        &mut self,
        offset: usize,
        new_str: &str,
        available_space: usize,
    ) -> error::Result<()> {
        let new_bytes = new_str.as_bytes();
        let new_len = new_bytes.len() + 1; // +1 for null terminator

        if new_len > available_space {
            return Err(error::Error::Malformed(
                "New string too long for available space".into(),
            ));
        }

        // Copy new string
        self.dynstrtab[offset..offset + new_bytes.len()].copy_from_slice(new_bytes);
        // Add null terminator
        self.dynstrtab[offset + new_bytes.len()] = 0;
        // Note: We don't pad with nulls - patchelf leaves 'X' taint characters after the new string

        Ok(())
    }

    /// Remove a dynamic section entry by tag.
    fn remove_dynamic_entry(&mut self, tag: u64) -> error::Result<()> {
        let entries = self
            .dynamic_entries
            .as_mut()
            .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

        // Remove the entry with the specified tag
        // The write_dynamic_section function will pad with DT_NULL entries
        entries.retain(|e| e.d_tag != tag);

        Ok(())
    }

    /// Add a string to the dynamic string table and return its offset.
    fn add_to_dynstrtab(&mut self, s: &str) -> usize {
        let offset = self.dynstrtab.len();
        self.dynstrtab.extend_from_slice(s.as_bytes());
        self.dynstrtab.push(0); // null terminator
        offset
    }

    /// Write the modified ELF file to a buffer.
    ///
    /// This creates a complete ELF file with all modifications applied.
    /// If the string table needs to grow beyond available slack space,
    /// this will relocate the section to the end of the file (library-style).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the complete modified ELF binary.
    pub fn write(&self) -> error::Result<Vec<u8>> {
        // Check if string table growth is needed
        let growth_needed = self.dynstrtab.len().saturating_sub(self.dynstrtab_size);

        if growth_needed > 0 {
            // Check for available slack space
            let slack_space = self.check_slack_space();

            if growth_needed <= slack_space {
                // We can use the slack space - simple in-place modification
                return self.write_with_slack();
            } else {
                // Relocate the section to the end of the file (library-style approach)
                return self.write_with_relocation();
            }
        }

        // No growth needed, proceed with simple write
        self.write_simple()
    }

    /// Write without any modifications (simple case).
    fn write_simple(&self) -> error::Result<Vec<u8>> {
        let mut output = self.data.to_vec();

        // Write modified dynamic section if it exists
        if let Some(ref entries) = self.dynamic_entries {
            self.write_dynamic_section(&mut output, entries)?;
        }

        // Write the modified dynamic string table (same size)
        if self.dynstrtab_offset + self.dynstrtab.len() <= output.len() {
            output[self.dynstrtab_offset..self.dynstrtab_offset + self.dynstrtab.len()]
                .copy_from_slice(&self.dynstrtab);
        }

        Ok(output)
    }

    /// Write using available slack space (no relocation needed).
    fn write_with_slack(&self) -> error::Result<Vec<u8>> {
        let mut output = self.data.to_vec();

        // Write the expanded dynamic string table into the existing slack space
        // The slack space check already verified this fits, so we can write directly
        let strtab_end = self.dynstrtab_offset + self.dynstrtab.len();
        if strtab_end > output.len() {
            return Err(error::Error::Malformed(
                "String table growth exceeds available slack space".into(),
            ));
        }
        output[self.dynstrtab_offset..strtab_end].copy_from_slice(&self.dynstrtab);

        // Write modified dynamic section with updated DT_STRSZ
        if let Some(ref entries) = self.dynamic_entries {
            // Update DT_STRSZ to reflect new size
            let mut updated_entries = entries.clone();
            for entry in &mut updated_entries {
                if entry.d_tag == goblin::elf::dynamic::DT_STRSZ {
                    entry.d_val = self.dynstrtab.len() as u64;
                }
            }
            self.write_dynamic_section(&mut output, &updated_entries)?;
        }

        // Update the dynamic string table section header size
        let mut updated_header = false;
        let sh_offset = self.header.e_shoff as usize;
        let sh_size = SectionHeader::size_with(&self.ctx);

        for (idx, section) in self.section_headers.iter().enumerate() {
            if section.sh_type == goblin::elf::section_header::SHT_STRTAB
                && section.sh_offset as usize == self.dynstrtab_offset
            {
                // Update this section header's size
                let mut updated_section = section.clone();
                updated_section.sh_size = self.dynstrtab.len() as u64;

                let header_offset = sh_offset + (idx * sh_size);
                if header_offset + sh_size <= output.len() {
                    updated_section.try_into_ctx(&mut output[header_offset..], self.ctx)?;
                    updated_header = true;
                }
                break;
            }
        }

        if !updated_header {
            return Err(error::Error::Malformed(
                "Could not update dynamic string table section header".into(),
            ));
        }

        Ok(output)
    }

    /// Write by appending to the end of the file (PIE/shared library approach).
    ///
    /// This implements patchelf's "append" approach for PIE binaries:
    /// - Appends space to the end of the file
    /// - Creates a new PT_LOAD segment at a higher virtual address
    /// - Relocates .dynstr and .dynamic to the appended space
    /// - Updates DT_STRTAB and DYNAMIC program header
    fn write_with_append(&self) -> error::Result<Vec<u8>> {
        const PAGE_SIZE: u64 = 0x1000; // 4KB pages

        // Find the highest virtual address and file offset currently in use
        let (highest_vaddr, _highest_file_end) = self
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .fold((0u64, 0usize), |(max_vaddr, max_offset), p| {
                let vaddr_end = p.p_vaddr + p.p_memsz;
                let offset_end = p.p_offset as usize + p.p_filesz as usize;
                (max_vaddr.max(vaddr_end), max_offset.max(offset_end))
            });

        // Round up to page boundary for the new segment
        let new_vaddr = (highest_vaddr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let new_file_offset =
            (self.data.len() + PAGE_SIZE as usize - 1) & !(PAGE_SIZE as usize - 1);

        // Calculate the content for the new segment
        // Layout: .dynstr (expanded) followed by .dynamic
        let dynstr_size = self.dynstrtab.len();
        let dyn_entry_size = Dyn::size_with(&self.ctx);
        let dynamic_size = self
            .dynamic_entries
            .as_ref()
            .map_or(0, |e| e.len() * dyn_entry_size);

        // Align dynamic section to 8 bytes
        let dynstr_padded_size = (dynstr_size + 7) & !7;
        let total_new_size = dynstr_padded_size + dynamic_size;

        // Create output buffer: original file + padding + new segment
        let _padding_size = new_file_offset - self.data.len();
        let new_total_size = new_file_offset + total_new_size;
        let mut output = vec![0u8; new_total_size];

        // Copy original file content
        output[..self.data.len()].copy_from_slice(self.data);

        // Fill original .dynstr with 'X' markers (patchelf behavior)
        for byte in &mut output[self.dynstrtab_offset..self.dynstrtab_offset + self.dynstrtab_size]
        {
            *byte = b'X';
        }

        // Write new .dynstr at the new location
        let new_dynstr_offset = new_file_offset;
        let new_dynstr_vaddr = new_vaddr;
        output[new_dynstr_offset..new_dynstr_offset + dynstr_size].copy_from_slice(&self.dynstrtab);

        // Write new .dynamic at the new location
        let new_dynamic_offset = new_file_offset + dynstr_padded_size;
        let new_dynamic_vaddr = new_vaddr + dynstr_padded_size as u64;

        if let Some(ref entries) = self.dynamic_entries {
            // Update DT_STRTAB and DT_STRSZ in dynamic entries
            let mut updated_entries = entries.clone();
            for entry in &mut updated_entries {
                match entry.d_tag {
                    goblin::elf::dynamic::DT_STRTAB => {
                        entry.d_val = new_dynstr_vaddr;
                    }
                    goblin::elf::dynamic::DT_STRSZ => {
                        entry.d_val = dynstr_size as u64;
                    }
                    _ => {}
                }
            }

            // Write dynamic entries
            for (i, entry) in updated_entries.iter().enumerate() {
                let pos = new_dynamic_offset + (i * dyn_entry_size);
                entry.clone().try_into_ctx(&mut output[pos..], self.ctx)?;
            }

            // Pad remaining with DT_NULL
            let null_entry = Dyn {
                d_tag: goblin::elf::dynamic::DT_NULL,
                d_val: 0,
            };
            for i in updated_entries.len()..self.original_dynamic_count {
                let pos = new_dynamic_offset + (i * dyn_entry_size);
                if pos + dyn_entry_size <= output.len() {
                    null_entry
                        .clone()
                        .try_into_ctx(&mut output[pos..], self.ctx)?;
                }
            }
        }

        // Update program headers
        // We need to: 1) add a new PT_LOAD for the appended segment
        //             2) update PT_DYNAMIC to point to new location
        let ph_size = ProgramHeader::size_with(&self.ctx);
        let old_ph_count = self.header.e_phnum as usize;
        let new_ph_count = old_ph_count + 1;

        // Check if there's room for an additional program header
        let ph_start = self.header.e_phoff as usize;
        let new_ph_end = ph_start + (new_ph_count * ph_size);

        // For PIE binaries, program headers are typically at offset 0x40 right after ELF header
        // We need to check if there's space or if we need to relocate them too
        // For simplicity, let's assume there's space (patchelf does complex relocation if not)

        // Write updated program headers
        for (i, phdr) in self.program_headers.iter().enumerate() {
            let mut updated = phdr.clone();

            // Update PT_DYNAMIC to point to new location
            if phdr.p_type == goblin::elf::program_header::PT_DYNAMIC {
                updated.p_offset = new_dynamic_offset as u64;
                updated.p_vaddr = new_dynamic_vaddr;
                updated.p_paddr = new_dynamic_vaddr;
                updated.p_filesz = dynamic_size as u64;
                updated.p_memsz = dynamic_size as u64;
            }

            let pos = ph_start + (i * ph_size);
            if pos + ph_size <= output.len() {
                updated.try_into_ctx(&mut output[pos..], self.ctx)?;
            }
        }

        // Add new PT_LOAD for the appended segment
        let new_pt_load = ProgramHeader {
            p_type: goblin::elf::program_header::PT_LOAD,
            p_flags: goblin::elf::program_header::PF_R | goblin::elf::program_header::PF_W,
            p_offset: new_file_offset as u64,
            p_vaddr: new_vaddr,
            p_paddr: new_vaddr,
            p_filesz: total_new_size as u64,
            p_memsz: total_new_size as u64,
            p_align: PAGE_SIZE,
        };

        // Write the new PT_LOAD at the end of program headers
        let new_ph_pos = ph_start + (old_ph_count * ph_size);
        if new_ph_pos + ph_size <= new_ph_end && new_ph_end <= output.len() {
            new_pt_load.try_into_ctx(&mut output[new_ph_pos..], self.ctx)?;

            // Update e_phnum in ELF header
            // For 64-bit ELF: e_phnum is at offset 0x38
            // For 32-bit ELF: e_phnum is at offset 0x2C
            let phnum_offset = if self.ctx.container.is_big() {
                0x38usize
            } else {
                0x2Cusize
            };
            if self.ctx.le.is_little() {
                let phnum_bytes = (new_ph_count as u16).to_le_bytes();
                output[phnum_offset] = phnum_bytes[0];
                output[phnum_offset + 1] = phnum_bytes[1];
            } else {
                let phnum_bytes = (new_ph_count as u16).to_be_bytes();
                output[phnum_offset] = phnum_bytes[0];
                output[phnum_offset + 1] = phnum_bytes[1];
            }
        }

        // Update section headers for .dynstr and .dynamic
        let sh_size = SectionHeader::size_with(&self.ctx);
        let sh_start = self.header.e_shoff as usize;

        for (i, section) in self.section_headers.iter().enumerate() {
            let mut updated = section.clone();

            // Update .dynstr section
            if section.sh_type == goblin::elf::section_header::SHT_STRTAB
                && section.sh_offset as usize == self.dynstrtab_offset
                && section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0
            {
                updated.sh_offset = new_dynstr_offset as u64;
                updated.sh_addr = new_dynstr_vaddr;
                updated.sh_size = dynstr_size as u64;
            }

            // Update .dynamic section
            if section.sh_type == goblin::elf::section_header::SHT_DYNAMIC {
                updated.sh_offset = new_dynamic_offset as u64;
                updated.sh_addr = new_dynamic_vaddr;
                updated.sh_size = dynamic_size as u64;
            }

            let pos = sh_start + (i * sh_size);
            if pos + sh_size <= output.len() {
                updated.try_into_ctx(&mut output[pos..], self.ctx)?;
            }
        }

        Ok(output)
    }

    /// Write by relocating the string table to the beginning of the file (prepend approach).
    ///
    /// This implements patchelf's "prepend" approach for non-PIE executables:
    /// - Prepends space to the beginning of the file
    /// - Creates a new PT_LOAD segment at a lower virtual address
    /// - Updates section headers and dynamic entries
    fn write_with_relocation(&self) -> error::Result<Vec<u8>> {
        const PAGE_SIZE: u64 = 0x1000; // 4KB pages
        const PREPEND_SIZE: usize = 0x2000; // 2 pages = 8KB prepended space

        // Find the lowest virtual address (typically 0x400000 for x86_64)
        let lowest_vaddr = self
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0x400000);

        // Check if we have enough virtual address space to prepend
        // For PIE binaries (low virtual addresses), use append approach instead
        if lowest_vaddr < PREPEND_SIZE as u64 {
            return self.write_with_append();
        }

        // New virtual address base is 2 pages below the original
        let new_vaddr_base = lowest_vaddr - PREPEND_SIZE as u64;

        // Calculate sizes
        let ph_size = ProgramHeader::size_with(&self.ctx);
        let sh_size = SectionHeader::size_with(&self.ctx);
        let old_ph_count = self.header.e_phnum as usize;
        let new_ph_count = old_ph_count + 1; // Adding one new PT_LOAD

        // Layout in prepended space:
        // 0x000: ELF header (64 bytes)
        // 0x040: Program headers (new_ph_count * 56 bytes)
        // After PHDRs: .note.gnu.build-id section (if exists)
        // After note: .dynstr section
        // Padding to alignment
        // 0x2000: Original file content starts

        let phdr_start = 0x40usize;
        let phdr_end = phdr_start + (new_ph_count * ph_size);

        // Find .note.gnu.build-id section
        let mut note_section_idx = None;
        let mut note_data: Vec<u8> = Vec::new();
        let mut note_orig_addr = 0u64;
        let mut note_orig_size = 0u64;

        for (idx, section) in self.section_headers.iter().enumerate() {
            if section.sh_type == goblin::elf::section_header::SHT_NOTE {
                // Check if this is .note.gnu.build-id by looking at the name
                // In practice, we relocate all SHT_NOTE sections with SHF_ALLOC
                if section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 {
                    note_section_idx = Some(idx);
                    note_orig_addr = section.sh_addr;
                    note_orig_size = section.sh_size;
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    if offset + size <= self.data.len() {
                        note_data = self.data[offset..offset + size].to_vec();
                    }
                    break;
                }
            }
        }

        // Calculate positions in prepended space
        // Align note section to 4 bytes
        let note_start_offset = (phdr_end + 3) & !3;
        let note_size = note_data.len();

        // .dynstr starts after note, aligned to 8 bytes
        let dynstr_start_offset = if note_size > 0 {
            (note_start_offset + note_size + 7) & !7
        } else {
            (phdr_end + 7) & !7
        };
        let dynstr_size = self.dynstrtab.len();

        // Total used space in prepended area (for the new PT_LOAD p_filesz/p_memsz)
        let used_prepend_space = (dynstr_start_offset + dynstr_size + 7) & !7;

        // Create the new output buffer
        let new_file_size = PREPEND_SIZE + self.data.len();
        let mut output = vec![0u8; new_file_size];

        // Copy original file content shifted by PREPEND_SIZE
        output[PREPEND_SIZE..].copy_from_slice(self.data);

        // Zero out the area where the original ELF header and relocated sections were.
        if note_orig_addr != 0 {
            let note_end_offset = (note_orig_addr + note_orig_size - lowest_vaddr) as usize;
            // Align to 4 bytes
            let clear_end = PREPEND_SIZE + ((note_end_offset + 3) & !3);
            for byte in &mut output[PREPEND_SIZE..clear_end] {
                *byte = 0;
            }
        }

        // Fill the original .dynstr location with 'Z' (patchelf convention)
        let orig_dynstr_new_offset = PREPEND_SIZE + self.dynstrtab_offset;
        for byte in
            &mut output[orig_dynstr_new_offset..orig_dynstr_new_offset + self.dynstrtab_size]
        {
            *byte = b'Z';
        }

        // Write new ELF header
        let mut new_header = self.header;
        new_header.e_phoff = phdr_start as u64;
        new_header.e_phnum = new_ph_count as u16;
        new_header.e_shoff = self.header.e_shoff + PREPEND_SIZE as u64;
        new_header.try_into_ctx(&mut output[..], self.ctx.le)?;

        // Build new program header table
        let mut new_phdrs: Vec<ProgramHeader> = Vec::with_capacity(new_ph_count);

        // First, add the new PT_LOAD for prepended space
        let new_pt_load = ProgramHeader {
            p_type: goblin::elf::program_header::PT_LOAD,
            p_flags: goblin::elf::program_header::PF_R | goblin::elf::program_header::PF_W,
            p_offset: 0,
            p_vaddr: new_vaddr_base,
            p_paddr: new_vaddr_base,
            p_filesz: used_prepend_space as u64,
            p_memsz: used_prepend_space as u64,
            p_align: PAGE_SIZE,
        };
        new_phdrs.push(new_pt_load);

        // Add updated versions of original program headers
        for phdr in &self.program_headers {
            let mut updated = phdr.clone();

            // Update file offset for all segments (shift by PREPEND_SIZE)
            // Exception: GNU_STACK has no file content, so keep offset 0
            if phdr.p_type == goblin::elf::program_header::PT_GNU_STACK {
                updated.p_offset = 0;
            } else {
                updated.p_offset = phdr.p_offset + PREPEND_SIZE as u64;
            }

            // Update PHDR segment to point to new location
            if phdr.p_type == goblin::elf::program_header::PT_PHDR {
                updated.p_offset = phdr_start as u64;
                updated.p_vaddr = new_vaddr_base + phdr_start as u64;
                updated.p_paddr = new_vaddr_base + phdr_start as u64;
                updated.p_filesz = (new_ph_count * ph_size) as u64;
                updated.p_memsz = (new_ph_count * ph_size) as u64;
            }

            // Update NOTE segment for .note.gnu.build-id to point to new location
            if phdr.p_type == goblin::elf::program_header::PT_NOTE
                && note_orig_addr != 0
                && phdr.p_vaddr == note_orig_addr
                && phdr.p_filesz == note_orig_size
            {
                updated.p_offset = note_start_offset as u64;
                updated.p_vaddr = new_vaddr_base + note_start_offset as u64;
                updated.p_paddr = new_vaddr_base + note_start_offset as u64;
            }

            // Shrink LOAD segment that originally contained .note.gnu.build-id
            if phdr.p_type == goblin::elf::program_header::PT_LOAD
                && note_orig_addr != 0
                && phdr.p_vaddr <= note_orig_addr
                && note_orig_addr < phdr.p_vaddr + phdr.p_filesz
                && (phdr.p_flags & goblin::elf::program_header::PF_X) != 0
            {
                // Find the section after .note.gnu.build-id (.init typically)
                let note_end = note_orig_addr + note_orig_size;
                // Align to 4 bytes
                let new_start = (note_end + 3) & !3;
                let shrink_amount = new_start - phdr.p_vaddr;

                updated.p_offset = phdr.p_offset + PREPEND_SIZE as u64 + shrink_amount;
                updated.p_vaddr = new_start;
                updated.p_paddr = new_start;
                updated.p_filesz = phdr.p_filesz - shrink_amount;
                updated.p_memsz = phdr.p_memsz - shrink_amount;
            }

            new_phdrs.push(updated);
        }

        // Sort program headers to match patchelf's ordering
        new_phdrs.sort_by(|a, b| {
            let order_a = Self::phdr_sort_order(a);
            let order_b = Self::phdr_sort_order(b);

            match order_a.cmp(&order_b) {
                std::cmp::Ordering::Equal => {
                    // Sort all same-priority segments by virtual address
                    a.p_vaddr.cmp(&b.p_vaddr)
                }
                other => other,
            }
        });

        // Write program headers
        for (idx, phdr) in new_phdrs.iter().enumerate() {
            let offset = phdr_start + (idx * ph_size);
            phdr.clone().try_into_ctx(&mut output[offset..], self.ctx)?;
        }

        // Write .note.gnu.build-id to prepended space
        if !note_data.is_empty() {
            output[note_start_offset..note_start_offset + note_size].copy_from_slice(&note_data);
        }

        // Write .dynstr to prepended space
        output[dynstr_start_offset..dynstr_start_offset + dynstr_size]
            .copy_from_slice(&self.dynstrtab);

        // Update section headers
        let new_sh_offset = new_header.e_shoff as usize;

        // First pass: create updated section headers
        let mut updated_sections: Vec<(usize, SectionHeader)> = Vec::new();

        for (idx, section) in self.section_headers.iter().enumerate() {
            let mut updated_section = section.clone();

            // Check if this is the .note.gnu.build-id section
            if Some(idx) == note_section_idx && !note_data.is_empty() {
                updated_section.sh_offset = note_start_offset as u64;
                updated_section.sh_addr = new_vaddr_base + note_start_offset as u64;
            }
            // Check if this is the .dynstr section
            else if section.sh_type == goblin::elf::section_header::SHT_STRTAB
                && section.sh_offset as usize == self.dynstrtab_offset
            {
                updated_section.sh_offset = dynstr_start_offset as u64;
                updated_section.sh_addr = new_vaddr_base + dynstr_start_offset as u64;
                updated_section.sh_size = dynstr_size as u64;
                // Patchelf changes alignment to 8 for relocated dynstr
                updated_section.sh_addralign = 8;
            }
            // All other sections: shift offset by PREPEND_SIZE (except SHT_NULL and non-ALLOC sections)
            else if section.sh_type != goblin::elf::section_header::SHT_NULL {
                if section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 {
                    updated_section.sh_offset = section.sh_offset + PREPEND_SIZE as u64;
                } else {
                    // Non-alloc sections (symtab, strtab, shstrtab, etc.) - just shift offset
                    updated_section.sh_offset = section.sh_offset + PREPEND_SIZE as u64;
                }
            }

            updated_sections.push((idx, updated_section));
        }

        // Sort sections by address
        updated_sections.sort_by(|a, b| {
            let (_, sec_a) = a;
            let (_, sec_b) = b;

            // NULL always first
            if sec_a.sh_type == goblin::elf::section_header::SHT_NULL {
                return std::cmp::Ordering::Less;
            }
            if sec_b.sh_type == goblin::elf::section_header::SHT_NULL {
                return std::cmp::Ordering::Greater;
            }

            // Non-ALLOC sections go to the end
            let a_alloc = sec_a.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0;
            let b_alloc = sec_b.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0;
            if a_alloc && !b_alloc {
                return std::cmp::Ordering::Less;
            }
            if !a_alloc && b_alloc {
                return std::cmp::Ordering::Greater;
            }

            // Sort ALLOC sections by address, non-ALLOC sections by offset
            if a_alloc {
                sec_a.sh_addr.cmp(&sec_b.sh_addr)
            } else {
                sec_a.sh_offset.cmp(&sec_b.sh_offset)
            }
        });

        // Build mapping from old index to new index
        let mut old_to_new_idx: Vec<usize> = vec![0; self.section_headers.len()];
        for (new_idx, (old_idx, _)) in updated_sections.iter().enumerate() {
            old_to_new_idx[*old_idx] = new_idx;
        }

        // Update sh_link fields to point to new indices
        for (_, section) in &mut updated_sections {
            if section.sh_link != 0 && (section.sh_link as usize) < old_to_new_idx.len() {
                section.sh_link = old_to_new_idx[section.sh_link as usize] as u32;
            }
        }

        // Write section headers in sorted order
        for (new_idx, (_, section)) in updated_sections.iter().enumerate() {
            let header_offset = new_sh_offset + (new_idx * sh_size);
            if header_offset + sh_size <= output.len() {
                section
                    .clone()
                    .try_into_ctx(&mut output[header_offset..], self.ctx)?;
            }
        }

        // Update symbol table entries to use new section indices
        for section in self.section_headers.iter() {
            if section.sh_type == goblin::elf::section_header::SHT_SYMTAB {
                let symtab_offset = section.sh_offset as usize + PREPEND_SIZE;
                let sym_size = section.sh_entsize as usize;
                let num_syms = section.sh_size as usize / sym_size;

                for i in 0..num_syms {
                    let sym_offset = symtab_offset + i * sym_size;
                    if sym_offset + sym_size <= output.len() {
                        // Read st_shndx (at offset 6 in Sym64, 2 bytes)
                        let shndx_offset = sym_offset + 6;
                        let old_shndx =
                            u16::from_le_bytes([output[shndx_offset], output[shndx_offset + 1]]);

                        // Update if it's a valid section index
                        if (old_shndx as usize) < old_to_new_idx.len() {
                            let new_shndx = old_to_new_idx[old_shndx as usize] as u16;
                            output[shndx_offset] = new_shndx as u8;
                            output[shndx_offset + 1] = (new_shndx >> 8) as u8;
                        }
                    }
                }
            }
        }

        // Update e_shstrndx in the ELF header to reflect new section ordering
        let old_shstrndx = self.header.e_shstrndx as usize;
        if old_shstrndx < old_to_new_idx.len() {
            let new_shstrndx = old_to_new_idx[old_shstrndx] as u16;
            // e_shstrndx is at offset 0x3E in a 64-bit ELF header
            output[0x3E] = new_shstrndx as u8;
            output[0x3F] = (new_shstrndx >> 8) as u8;
        }

        // Update dynamic entries (DT_STRTAB and DT_STRSZ)
        if let Some(ref entries) = self.dynamic_entries {
            let new_dynstr_vaddr = new_vaddr_base + dynstr_start_offset as u64;

            let mut updated_entries = entries.clone();
            for entry in &mut updated_entries {
                if entry.d_tag == goblin::elf::dynamic::DT_STRTAB {
                    entry.d_val = new_dynstr_vaddr;
                } else if entry.d_tag == goblin::elf::dynamic::DT_STRSZ {
                    entry.d_val = dynstr_size as u64;
                }
            }

            // Write to the shifted dynamic section offset
            self.write_dynamic_section_at_offset(&mut output, &updated_entries, PREPEND_SIZE)?;
        }

        Ok(output)
    }

    /// Write dynamic section entries at a specific additional offset
    fn write_dynamic_section_at_offset(
        &self,
        output: &mut [u8],
        entries: &[Dyn],
        offset_shift: usize,
    ) -> error::Result<()> {
        // Find the dynamic section
        for section in &self.section_headers {
            if section.sh_type == goblin::elf::section_header::SHT_DYNAMIC {
                let shifted_offset = section.sh_offset as usize + offset_shift;
                let entry_size = core::mem::size_of::<u64>() * 2; // d_tag + d_val

                for (idx, entry) in entries.iter().enumerate() {
                    let entry_offset = shifted_offset + (idx * entry_size);
                    if entry_offset + entry_size <= output.len() {
                        entry
                            .clone()
                            .try_into_ctx(&mut output[entry_offset..], self.ctx)?;
                    }
                }
                break;
            }
        }
        Ok(())
    }

    /// Check how much slack space (unused space) exists after the string table.
    fn check_slack_space(&self) -> usize {
        // Find the offset of the next section after the dynamic string table
        let next_section_offset = self
            .section_headers
            .iter()
            .filter(|s| s.sh_offset > self.dynstrtab_offset as u64)
            .map(|s| s.sh_offset as usize)
            .min();

        // If there's no section after dynstr, there's no slack space
        let next_offset = match next_section_offset {
            Some(offset) => offset,
            None => return 0,
        };

        // Calculate slack space between current end and next section
        let current_end = self.dynstrtab_offset + self.dynstrtab_size;
        next_offset.saturating_sub(current_end)
    }

    /// Write the dynamic section to the output buffer.
    fn write_dynamic_section(&self, output: &mut [u8], entries: &[Dyn]) -> error::Result<()> {
        use scroll::ctx::TryIntoCtx;

        // Find the dynamic section in program headers
        let mut dynamic_offset = None;
        for ph in &self.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_DYNAMIC {
                dynamic_offset = Some(ph.p_offset as usize);
                break;
            }
        }

        let offset = dynamic_offset
            .ok_or_else(|| error::Error::Malformed("No PT_DYNAMIC segment found".into()))?;

        // Write each dynamic entry
        use scroll::ctx::SizeWith;
        let entry_size = Dyn::size_with(&self.ctx);
        for (i, entry) in entries.iter().enumerate() {
            let pos = offset + (i * entry_size);
            if pos + entry_size > output.len() {
                return Err(error::Error::Malformed(
                    "Dynamic section extends beyond file size".into(),
                ));
            }

            entry.clone().try_into_ctx(&mut output[pos..], self.ctx)?;
        }

        // Pad remaining slots with DT_NULL entries (needed when entries were removed)
        let null_entry = Dyn {
            d_tag: goblin::elf::dynamic::DT_NULL,
            d_val: 0,
        };
        for i in entries.len()..self.original_dynamic_count {
            let pos = offset + (i * entry_size);
            if pos + entry_size > output.len() {
                break;
            }
            null_entry
                .clone()
                .try_into_ctx(&mut output[pos..], self.ctx)?;
        }

        Ok(())
    }

    /// Get the sort order priority for a program header type.
    fn phdr_sort_order(phdr: &ProgramHeader) -> u32 {
        use goblin::elf::program_header::*;
        match phdr.p_type {
            PT_PHDR => 0,      // PHDR must come first
            PT_GNU_STACK => 1, // GNU_STACK comes second in patchelf
            _ => 2,            // Everything else sorted by vaddr
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_writer_creation() {
        // This test would require actual ELF binary data
        // We'll add proper tests with real binaries later
    }
}
