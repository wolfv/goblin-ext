//! ELF file writing and modification support.
//!
//! This module provides functionality for writing and modifying ELF files,
//! including support for changing dynamic section entries like RPATH/RUNPATH.
//!
//! The writer supports automatic section relocation when string tables need to grow,
//! adding new PT_LOAD segments as needed to accommodate relocated sections.
//!
//! # Page Size and Alignment
//!
//! ELF files require careful attention to page size and segment alignment.
//! Different CPU architectures have different page sizes:
//!
//! - **4KB (0x1000)**: x86, x86_64, ARM32 - most common page size
//! - **8KB (0x2000)**: SPARC - uses 8KB pages
//! - **64KB (0x10000)**: IA-64, MIPS, PowerPC, PowerPC64, AArch64, TileGX, LoongArch
//!
//! The page size affects PT_LOAD segment alignment. When adding new segments
//! or relocating sections, we must respect the architecture's page size to
//! ensure the binary can be loaded correctly.
//!
//! ## Segment Alignment Invariant
//!
//! For PT_LOAD segments, the ELF specification requires:
//! ```text
//! (p_vaddr - p_offset) % p_align == 0
//! ```
//!
//! This ensures that when the segment is mapped into memory, the file offset
//! and virtual address maintain proper alignment. If this invariant is violated,
//! the loader may fail or produce incorrect behavior.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use goblin::container::Ctx;
use goblin::elf::dynamic::Dyn;
use goblin::elf::header::{Header, EM_AARCH64, EM_IA_64, EM_MIPS, EM_PPC, EM_PPC64, EM_SPARC, EM_SPARCV9};
use goblin::elf::program_header::ProgramHeader;
use goblin::elf::section_header::SectionHeader;
use goblin::error;
use scroll::{ctx::SizeWith, ctx::TryIntoCtx, Pread};

// Architecture-specific e_machine constants not exported by goblin
// See: ELF specification and Linux kernel's include/uapi/linux/elf-em.h
const EM_TILEGX: u16 = 191;
const EM_LOONGARCH: u16 = 258;

/// Default section alignment (1 byte, no padding between sections)
const SECTION_ALIGNMENT: usize = 1;

/// A builder for modifying and writing ELF files.
///
/// This struct allows you to load an existing ELF file, modify various
/// components (like dynamic section entries), and write it back out.
/// When sections need to grow beyond their original space, they are
/// relocated to a new PT_LOAD segment at the end of the file.
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
    /// Section names string table
    section_names: Vec<u8>,
    /// Dynamic section entries (if present)
    dynamic_entries: Option<Vec<Dyn>>,
    /// Original number of dynamic entries
    original_dynamic_count: usize,
    /// Modified dynamic string table
    dynstrtab: Vec<u8>,
    /// Original dynamic string table offset
    dynstrtab_offset: usize,
    /// Context (endianness, container size)
    ctx: Ctx,
    /// Sections marked for relocation (name -> new content)
    replaced_sections: BTreeMap<String, Vec<u8>>,
}

impl<'a> ElfWriter<'a> {
    /// Create a new ElfWriter from an existing ELF binary.
    pub fn new(data: &'a [u8], elf: &goblin::elf::Elf) -> error::Result<Self> {
        let (dynstrtab, dynstrtab_offset) = if let Some(ref dynamic) = elf.dynamic {
            let offset = dynamic.info.strtab;
            let size = dynamic.info.strsz;
            if offset + size <= data.len() {
                (data[offset..offset + size].to_vec(), offset)
            } else {
                (Vec::new(), 0)
            }
        } else {
            (Vec::new(), 0)
        };

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

        // Get section names string table
        let shstrtab_idx = elf.header.e_shstrndx as usize;
        let section_names = if shstrtab_idx < elf.section_headers.len() {
            let shdr = &elf.section_headers[shstrtab_idx];
            let start = shdr.sh_offset as usize;
            let end = start + shdr.sh_size as usize;
            if end <= data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(ElfWriter {
            data,
            header: elf.header,
            program_headers: elf.program_headers.clone(),
            section_headers: elf.section_headers.clone(),
            section_names,
            dynamic_entries,
            original_dynamic_count,
            dynstrtab,
            dynstrtab_offset,
            ctx,
            replaced_sections: BTreeMap::new(),
        })
    }

    /// Get section name from section header
    fn get_section_name(&self, shdr: &SectionHeader) -> String {
        let name_off = shdr.sh_name;
        if name_off >= self.section_names.len() {
            return String::new();
        }
        let end = self.section_names[name_off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.section_names.len() - name_off);
        String::from_utf8_lossy(&self.section_names[name_off..name_off + end]).into_owned()
    }

    /// Find section header by name
    fn find_section_header(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers
            .iter()
            .find(|shdr| self.get_section_name(shdr) == name)
    }

    /// Check if a section has been marked for replacement
    fn has_replaced_section(&self, name: &str) -> bool {
        self.replaced_sections.contains_key(name)
    }

    /// Check if a section can be replaced (relocated to new segment)
    fn can_replace_section(&self, name: &str) -> bool {
        if name == ".interp" {
            return true;
        }
        if let Some(shdr) = self.find_section_header(name) {
            return shdr.sh_type != goblin::elf::section_header::SHT_PROGBITS;
        }
        false
    }

    /// Mark a section for replacement with new content (or resize existing)
    fn replace_section(&mut self, name: &str, new_size: usize) {
        let content = if let Some(existing) = self.replaced_sections.get(name) {
            let mut content = existing.clone();
            content.resize(new_size, 0);
            content
        } else if let Some(shdr) = self.find_section_header(name) {
            let offset = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            let mut content = if offset + size <= self.data.len() {
                self.data[offset..offset + size].to_vec()
            } else {
                vec![0u8; size]
            };
            content.resize(new_size, 0);
            content
        } else {
            vec![0u8; new_size]
        };
        self.replaced_sections.insert(name.to_string(), content);
    }

    /// Set the RPATH or RUNPATH in the dynamic section.
    pub fn set_rpath(&mut self, rpath: &str, force_rpath: bool) -> error::Result<()> {
        let target_tag = if force_rpath {
            goblin::elf::dynamic::DT_RPATH
        } else {
            goblin::elf::dynamic::DT_RUNPATH
        };
        let other_tag = if force_rpath {
            goblin::elf::dynamic::DT_RUNPATH
        } else {
            goblin::elf::dynamic::DT_RPATH
        };

        // First, gather information without holding mutable borrow
        let (entry_idx, rpath_offset, rpath_size) = {
            let entries = self
                .dynamic_entries
                .as_ref()
                .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

            let entry_idx = entries
                .iter()
                .position(|e| e.d_tag == target_tag || e.d_tag == other_tag);

            let (rpath_offset, rpath_size) = if let Some(idx) = entry_idx {
                let offset = entries[idx].d_val as usize;
                let end = self.dynstrtab[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                (offset, end)
            } else {
                (0, 0)
            };

            (entry_idx, rpath_offset, rpath_size)
        };

        let needs_relocation = rpath.len() > rpath_size || entry_idx.is_none();

        if needs_relocation {
            // Get dynamic section size before modifying
            let dynamic_size = self
                .find_section_header(".dynamic")
                .map(|s| s.sh_size as usize)
                .unwrap_or(0);

            // Copy dynstrtab for later use
            let old_dynstrtab = self.dynstrtab.clone();
            let old_dynstrtab_len = old_dynstrtab.len();

            // Mark .dynstr for replacement with new size
            let new_dynstr_size = old_dynstrtab_len + rpath.len() + 1;
            self.replace_section(".dynstr", new_dynstr_size);

            // Build new dynstr content
            {
                let dynstr = self.replaced_sections.get_mut(".dynstr").unwrap();
                dynstr[..old_dynstrtab_len].copy_from_slice(&old_dynstrtab);
                dynstr[old_dynstrtab_len..old_dynstrtab_len + rpath.len()]
                    .copy_from_slice(rpath.as_bytes());
                dynstr[old_dynstrtab_len + rpath.len()] = 0;

                // Taint old rpath with 'X'
                if rpath_offset > 0 && rpath_size > 0 {
                    for i in 0..rpath_size {
                        if rpath_offset + i < dynstr.len() {
                            dynstr[rpath_offset + i] = b'X';
                        }
                    }
                }
            }

            // Now update dynamic entries
            let entries = self.dynamic_entries.as_mut().unwrap();
            if let Some(idx) = entry_idx {
                entries[idx].d_val = old_dynstrtab_len as u64;
                entries[idx].d_tag = target_tag;
            } else {
                // Need to grow .dynamic section
                let new_dynamic_size = dynamic_size + core::mem::size_of::<Dyn>();
                self.replace_section(".dynamic", new_dynamic_size);

                let new_entry = Dyn {
                    d_tag: target_tag,
                    d_val: old_dynstrtab_len as u64,
                };
                let entries = self.dynamic_entries.as_mut().unwrap();
                entries.insert(0, new_entry);
            }
        } else {
            // Fits in existing space - modify in place
            for i in 0..rpath_size {
                if rpath_offset + i < self.dynstrtab.len() {
                    self.dynstrtab[rpath_offset + i] = b'X';
                }
            }
            self.dynstrtab[rpath_offset..rpath_offset + rpath.len()]
                .copy_from_slice(rpath.as_bytes());
            self.dynstrtab[rpath_offset + rpath.len()] = 0;

            if let Some(idx) = entry_idx {
                let entries = self.dynamic_entries.as_mut().unwrap();
                entries[idx].d_tag = target_tag;
            }
        }

        Ok(())
    }

    /// Remove the RPATH from the dynamic section.
    pub fn remove_rpath(&mut self) -> error::Result<()> {
        let entries = self
            .dynamic_entries
            .as_mut()
            .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

        // Find and remove RPATH entry
        if let Some(idx) = entries
            .iter()
            .position(|e| e.d_tag == goblin::elf::dynamic::DT_RPATH)
        {
            // Get rpath offset to taint it
            let rpath_offset = entries[idx].d_val as usize;
            let rpath_end = self.dynstrtab[rpath_offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(0);

            // Taint the old rpath
            for i in 0..rpath_end {
                if rpath_offset + i < self.dynstrtab.len() {
                    self.dynstrtab[rpath_offset + i] = b'X';
                }
            }

            entries.remove(idx);
        }

        Ok(())
    }

    /// Remove the RUNPATH from the dynamic section.
    pub fn remove_runpath(&mut self) -> error::Result<()> {
        let entries = self
            .dynamic_entries
            .as_mut()
            .ok_or_else(|| error::Error::Malformed("No dynamic section found".into()))?;

        if let Some(idx) = entries
            .iter()
            .position(|e| e.d_tag == goblin::elf::dynamic::DT_RUNPATH)
        {
            let rpath_offset = entries[idx].d_val as usize;
            let rpath_end = self.dynstrtab[rpath_offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(0);

            for i in 0..rpath_end {
                if rpath_offset + i < self.dynstrtab.len() {
                    self.dynstrtab[rpath_offset + i] = b'X';
                }
            }

            entries.remove(idx);
        }

        Ok(())
    }

    /// Build the modified ELF file.
    pub fn build(&mut self) -> error::Result<Vec<u8>> {
        if self.replaced_sections.is_empty() {
            // No sections need relocation - simple case
            return self.write_simple();
        }

        // Relocate sections to a new segment
        self.rewrite_sections_library()
    }

    /// Write without any relocation (simple case).
    fn write_simple(&self) -> error::Result<Vec<u8>> {
        let mut output = self.data.to_vec();

        // Write modified dynamic section if it exists
        if let Some(ref entries) = self.dynamic_entries {
            self.write_dynamic_section(&mut output, entries)?;
        }

        // Write the modified dynamic string table
        if self.dynstrtab_offset + self.dynstrtab.len() <= output.len() {
            output[self.dynstrtab_offset..self.dynstrtab_offset + self.dynstrtab.len()]
                .copy_from_slice(&self.dynstrtab);
        }

        Ok(output)
    }

    /// Round up to alignment
    fn round_up(value: usize, alignment: usize) -> usize {
        if alignment == 0 {
            return value;
        }
        (value + alignment - 1) & !(alignment - 1)
    }

    /// Get the page size for the target architecture.
    ///
    /// Page sizes are defined by each CPU architecture. The page size is critical
    /// for correctly aligning PT_LOAD segments. Using the wrong page size can cause:
    /// - Loader failures on the target architecture
    /// - Incorrect memory mappings
    /// - Security issues if pages aren't properly aligned for protection
    ///
    /// # Page Sizes by Architecture
    ///
    /// | Page Size      | Architectures                                               |
    /// |----------------|-------------------------------------------------------------|
    /// | 64KB (0x10000) | IA-64, MIPS, PowerPC, PowerPC64, AArch64, TileGX, LoongArch |
    /// | 8KB (0x2000)   | SPARC, SPARC64                                              |
    /// | 4KB (0x1000)   | x86, x86_64, ARM32, and all others (default)                |
    ///
    /// Note: While some systems (like Linux on AArch64) may support 4KB pages,
    /// we use the maximum page size for the architecture to ensure compatibility
    /// with all configurations.
    fn get_page_size(&self) -> usize {
        match self.header.e_machine {
            // 64KB page size architectures
            // These architectures may support smaller pages but 64KB is the safe choice
            EM_IA_64 | EM_MIPS | EM_PPC | EM_PPC64 | EM_AARCH64 | EM_TILEGX | EM_LOONGARCH => {
                0x10000
            }
            // 8KB page size architectures (SPARC)
            EM_SPARC | EM_SPARCV9 => 0x2000,
            // Default 4KB page size (x86, x86_64, ARM32, etc.)
            _ => 0x1000,
        }
    }

    /// Fix misaligned PT_LOAD segments by adjusting their p_align value.
    ///
    /// When a segment violates the ELF alignment invariant
    /// `(p_vaddr - p_offset) % p_align == 0`, we reset its alignment to the
    /// architecture's page size.
    ///
    /// This typically happens when a binary was produced with unusual alignment
    /// requirements or has been modified incorrectly. Setting p_align to the
    /// page size is a safe fix since page alignment is the minimum required
    /// for memory mapping.
    fn fix_segment_alignment(&mut self) {
        let page_size = self.get_page_size() as u64;
        for phdr in &mut self.program_headers {
            if phdr.p_align != 0 && phdr.p_type == goblin::elf::program_header::PT_LOAD {
                let vaddr = phdr.p_vaddr;
                let offset = phdr.p_offset;
                // Check if (p_vaddr - p_offset) % p_align != 0
                if (vaddr.wrapping_sub(offset)) % phdr.p_align != 0 {
                    // Fix by setting alignment to page size
                    phdr.p_align = page_size;
                }
            }
        }
    }

    /// Relocate sections to a new PT_LOAD segment at the end of the file.
    ///
    /// This is used when sections (like .dynstr) need to grow beyond their
    /// original allocated space. The approach:
    /// 1. Allocate a new PT_LOAD segment at a page-aligned address after the last segment
    /// 2. Copy relocated sections to the new segment
    /// 3. Update all section headers and program headers to point to new locations
    /// 4. Update dynamic section entries (DT_STRTAB, etc.) with new addresses
    fn rewrite_sections_library(&mut self) -> error::Result<Vec<u8>> {
        // Fix any misaligned segments before proceeding
        self.fix_segment_alignment();

        // Get architecture-specific page size
        let page_size = self.get_page_size();

        // Find the highest virtual address end
        let mut start_page: usize = 0;
        let mut first_page: usize = 0;
        for phdr in &self.program_headers {
            let this_page = (phdr.p_vaddr + phdr.p_memsz) as usize;
            if this_page > start_page {
                start_page = this_page;
            }
            if phdr.p_type == goblin::elf::program_header::PT_PHDR {
                first_page = (phdr.p_vaddr - phdr.p_offset) as usize;
            }
        }
        start_page = Self::round_up(start_page, page_size);

        // Calculate PHT size (for determining which sections to auto-replace)
        // PHT = ELF header + program headers. Sections overlapping with PHT must be relocated.
        // num_notes accounts for worst case where each SHT_NOTE section needs its own PT_NOTE
        let num_notes = self
            .section_headers
            .iter()
            .filter(|s| s.sh_type == goblin::elf::section_header::SHT_NOTE)
            .count();
        let num_phdrs = self.program_headers.len() + num_notes + 1; // +num_notes for PT_NOTE, +1 for new PT_LOAD
        let ehdr_size = if self.ctx.container.is_big() { 64 } else { 52 };
        let phdr_size = ProgramHeader::size_with(&self.ctx);
        let pht_size = Self::round_up(ehdr_size + num_phdrs * phdr_size, SECTION_ALIGNMENT);

        // Auto-replace sections that fall within the PHT area
        // This ensures sections like .hash, .gnu.hash get relocated along with .dynstr
        // We use <= because sections at exactly pht_size boundary should also be relocated
        let mut sections_to_replace: Vec<(String, usize)> = Vec::new();
        for (i, shdr) in self.section_headers.iter().enumerate() {
            if i == 0 {
                continue; // Skip NULL section
            }
            let section_name = self.get_section_name(shdr);
            if (shdr.sh_offset as usize) <= pht_size
                && !self.has_replaced_section(&section_name) && self.can_replace_section(&section_name) {
                    sections_to_replace.push((section_name, shdr.sh_size as usize));
                }
        }
        for (name, size) in sections_to_replace {
            self.replace_section(&name, size);
        }

        // Calculate sizes
        let sh_size = SectionHeader::size_with(&self.ctx);
        let _sht_size = Self::round_up(self.section_headers.len() * sh_size, SECTION_ALIGNMENT);

        // Calculate needed space: sum of section sizes with their alignments
        // Iterate sections in order to properly account for alignment gaps
        let mut needed_space = 0usize;
        for shdr in &self.section_headers {
            let section_name = self.get_section_name(shdr);
            if let Some(content) = self.replaced_sections.get(&section_name) {
                let section_align = if shdr.sh_type == goblin::elf::section_header::SHT_NOTE {
                    shdr.sh_addralign.max(8) as usize
                } else {
                    shdr.sh_addralign.max(1) as usize
                };
                needed_space = Self::round_up(needed_space, section_align);
                needed_space += content.len();
            }
        }

        // Calculate file offset (page-aligned from end of file)
        let start_offset = Self::round_up(self.data.len(), page_size);

        // Binutils 2.30 quirk: older versions of readelf checked if dynamic section
        // segment size was *strictly less than* file size (not <=). Adding 1 byte
        // of padding ensures the file is always larger than any segment, avoiding
        // false "segment extends beyond end of file" errors in old tools.
        let binutils_quirk_padding = 1usize;
        let new_file_size = start_offset + needed_space + binutils_quirk_padding;

        // Create output buffer
        let mut output = vec![0u8; new_file_size];
        output[..self.data.len()].copy_from_slice(self.data);

        // Clobber original section locations with 'X' to make debugging easier
        for name in self.replaced_sections.keys() {
            if let Some(shdr) = self.find_section_header(name) {
                if shdr.sh_type != goblin::elf::section_header::SHT_NOBITS {
                    let offset = shdr.sh_offset as usize;
                    let size = shdr.sh_size as usize;
                    if offset + size <= output.len() {
                        for byte in &mut output[offset..offset + size] {
                            *byte = b'X';
                        }
                    }
                }
            }
        }

        // Try to expand last PT_LOAD segment, or create new one
        let mut expanded_last_load = false;
        let mut last_seg_addr = start_page;

        if let Some(last_load) = self
            .program_headers
            .iter_mut()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .last()
        {
            if last_load.p_flags
                == (goblin::elf::program_header::PF_R | goblin::elf::program_header::PF_W)
                && last_load.p_align as usize == page_size
            {
                let seg_end = Self::round_up(
                    (last_load.p_offset + last_load.p_memsz) as usize,
                    page_size,
                );
                if seg_end == start_offset {
                    // Can expand this segment
                    expanded_last_load = true;
                    let new_sz = start_offset + needed_space - last_load.p_offset as usize;
                    last_seg_addr = last_load.p_vaddr as usize + new_sz - needed_space;
                    last_load.p_filesz = new_sz as u64;
                    last_load.p_memsz = new_sz as u64;
                }
            }
        }

        if !expanded_last_load {
            // Add new PT_LOAD segment
            let new_pt_load = ProgramHeader {
                p_type: goblin::elf::program_header::PT_LOAD,
                p_flags: goblin::elf::program_header::PF_R | goblin::elf::program_header::PF_W,
                p_offset: start_offset as u64,
                p_vaddr: start_page as u64,
                p_paddr: start_page as u64,
                p_filesz: needed_space as u64,
                p_memsz: needed_space as u64,
                p_align: page_size as u64,
            };
            self.program_headers.push(new_pt_load);
            self.header.e_phnum = self.program_headers.len() as u16;
            last_seg_addr = start_page;
        }

        // Layout in new segment: sections only (SHT stays at original location)
        // We update section headers in place, keeping them at original file offset
        let mut cur_off = start_offset;

        // Write replaced sections and update section headers
        // Iterate in section header order to maintain relative positions
        let mut section_new_offsets: BTreeMap<String, (usize, usize)> = BTreeMap::new(); // name -> (offset, vaddr)

        for shdr in &self.section_headers {
            let section_name = self.get_section_name(shdr);
            if let Some(content) = self.replaced_sections.get(&section_name) {
                // Align cur_off to section's alignment
                // NOTE sections need at least 8-byte alignment for proper parsing
                let section_align = if shdr.sh_type == goblin::elf::section_header::SHT_NOTE {
                    shdr.sh_addralign.max(8) as usize
                } else {
                    shdr.sh_addralign.max(1) as usize
                };
                cur_off = Self::round_up(cur_off, section_align);

                let new_offset = cur_off;
                let new_vaddr = last_seg_addr + (cur_off - start_offset);

                // Write section content
                output[new_offset..new_offset + content.len()].copy_from_slice(content);

                section_new_offsets.insert(section_name, (new_offset, new_vaddr));
                cur_off += content.len();
            }
        }

        // Update section headers with new offsets/addresses
        // First collect section names to avoid borrow issues
        let section_names_list: Vec<String> = self
            .section_headers
            .iter()
            .map(|shdr| self.get_section_name(shdr))
            .collect();

        for (shdr, section_name) in self.section_headers.iter_mut().zip(section_names_list.iter()) {
            if let Some((new_offset, new_vaddr)) = section_new_offsets.get(section_name) {
                let new_size = self.replaced_sections.get(section_name).map(|c| c.len()).unwrap_or(0);
                shdr.sh_offset = *new_offset as u64;
                shdr.sh_addr = *new_vaddr as u64;
                shdr.sh_size = new_size as u64;
                shdr.sh_addralign = SECTION_ALIGNMENT as u64;
            }
        }

        // Update PT_DYNAMIC segment if .dynamic was relocated
        if let Some((new_offset, new_vaddr)) = section_new_offsets.get(".dynamic") {
            for phdr in &mut self.program_headers {
                if phdr.p_type == goblin::elf::program_header::PT_DYNAMIC {
                    let new_size = self.replaced_sections.get(".dynamic").map(|c| c.len()).unwrap_or(0);
                    phdr.p_offset = *new_offset as u64;
                    phdr.p_vaddr = *new_vaddr as u64;
                    phdr.p_paddr = *new_vaddr as u64;
                    phdr.p_filesz = new_size as u64;
                    phdr.p_memsz = new_size as u64;
                }
            }
        }

        // Update PT_INTERP segment if .interp was relocated
        if let Some((new_offset, new_vaddr)) = section_new_offsets.get(".interp") {
            for phdr in &mut self.program_headers {
                if phdr.p_type == goblin::elf::program_header::PT_INTERP {
                    let new_size = self.replaced_sections.get(".interp").map(|c| c.len()).unwrap_or(0);
                    phdr.p_offset = *new_offset as u64;
                    phdr.p_vaddr = *new_vaddr as u64;
                    phdr.p_paddr = *new_vaddr as u64;
                    phdr.p_filesz = new_size as u64;
                    phdr.p_memsz = new_size as u64;
                }
            }
        }

        // Update PT_NOTE segments to point to relocated NOTE sections
        // Each PT_NOTE segment should map to exactly one NOTE section
        let note_sections: Vec<(String, u64, u64, u64)> = section_names_list
            .iter()
            .zip(self.section_headers.iter())
            .filter(|(name, shdr)| {
                shdr.sh_type == goblin::elf::section_header::SHT_NOTE
                    && section_new_offsets.contains_key(*name)
            })
            .map(|(name, shdr)| (name.clone(), shdr.sh_offset, shdr.sh_addr, shdr.sh_size))
            .collect();

        // Update existing PT_NOTE segments to point to new locations
        // Track which PT_NOTE indices we've updated
        let mut updated_note_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();

        for (_name, new_off, new_addr, new_size) in &note_sections {
            // Find and update the next available PT_NOTE segment
            for (idx, phdr) in self.program_headers.iter_mut().enumerate() {
                if phdr.p_type == goblin::elf::program_header::PT_NOTE
                    && !updated_note_indices.contains(&idx)
                {
                    // Try to match based on the fact that after normalization,
                    // each PT_NOTE should map to exactly one section
                    // For simplicity, update the first unmatched PT_NOTE we find
                    phdr.p_offset = *new_off;
                    phdr.p_vaddr = *new_addr;
                    phdr.p_paddr = *new_addr;
                    phdr.p_filesz = *new_size;
                    phdr.p_memsz = *new_size;
                    updated_note_indices.insert(idx);
                    break;
                }
            }
        }

        // If we have more NOTE sections than PT_NOTE segments, add new ones
        let existing_note_count = self
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_NOTE)
            .count();
        let remaining_notes: Vec<_> = note_sections
            .iter()
            .skip(existing_note_count)
            .collect();

        for (_, new_off, new_addr, new_size) in remaining_notes {
            let new_note = ProgramHeader {
                p_type: goblin::elf::program_header::PT_NOTE,
                p_flags: goblin::elf::program_header::PF_R,
                p_offset: *new_off,
                p_vaddr: *new_addr,
                p_paddr: *new_addr,
                p_filesz: *new_size,
                p_memsz: *new_size,
                p_align: 4, // NOTE sections typically have 4 or 8 byte alignment
            };
            self.program_headers.push(new_note);
        }
        self.header.e_phnum = self.program_headers.len() as u16;

        // Update PT_GNU_PROPERTY if .note.gnu.property was relocated
        if let Some((new_offset, new_vaddr)) = section_new_offsets.get(".note.gnu.property") {
            let new_size = self.replaced_sections.get(".note.gnu.property").map(|c| c.len()).unwrap_or(0);
            for phdr in &mut self.program_headers {
                if phdr.p_type == goblin::elf::program_header::PT_GNU_PROPERTY {
                    phdr.p_offset = *new_offset as u64;
                    phdr.p_vaddr = *new_vaddr as u64;
                    phdr.p_paddr = *new_vaddr as u64;
                    phdr.p_filesz = new_size as u64;
                    phdr.p_memsz = new_size as u64;
                }
            }
        }

        // Update PT_PHDR segment
        let phdr_addr = first_page + self.header.e_phoff as usize;
        let phdr_total_size = (self.program_headers.len() * phdr_size) as u64;
        for phdr in &mut self.program_headers {
            if phdr.p_type == goblin::elf::program_header::PT_PHDR {
                phdr.p_offset = self.header.e_phoff;
                phdr.p_vaddr = phdr_addr as u64;
                phdr.p_paddr = phdr_addr as u64;
                phdr.p_filesz = phdr_total_size;
                phdr.p_memsz = phdr_total_size;
            }
        }

        // Sort program headers: PT_PHDR first, then by virtual address
        self.program_headers.sort_by(|a, b| {
            // PT_PHDR must come first per ELF spec
            if a.p_type == goblin::elf::program_header::PT_PHDR {
                return core::cmp::Ordering::Less;
            }
            if b.p_type == goblin::elf::program_header::PT_PHDR {
                return core::cmp::Ordering::Greater;
            }
            // Then by vaddr
            a.p_vaddr.cmp(&b.p_vaddr)
        });

        // Sort section headers by offset for canonical ordering
        // Keep index 0 (NULL section) in place as required by ELF spec
        let mut indexed_shdrs: Vec<(usize, SectionHeader)> = self
            .section_headers
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.clone()))
            .collect();
        indexed_shdrs[1..].sort_by(|a, b| a.1.sh_offset.cmp(&b.1.sh_offset));

        // Build old-to-new index mapping
        let mut old_to_new: Vec<usize> = vec![0; self.section_headers.len()];
        for (new_idx, (old_idx, _)) in indexed_shdrs.iter().enumerate() {
            old_to_new[*old_idx] = new_idx;
        }

        // Update sh_link fields
        for (_, shdr) in &mut indexed_shdrs {
            if shdr.sh_link != 0 && (shdr.sh_link as usize) < old_to_new.len() {
                shdr.sh_link = old_to_new[shdr.sh_link as usize] as u32;
            }
            if shdr.sh_info != 0
                && shdr.sh_type == goblin::elf::section_header::SHT_SYMTAB
                && (shdr.sh_info as usize) < old_to_new.len()
            {
                shdr.sh_info = old_to_new[shdr.sh_info as usize] as u32;
            }
        }

        // Update e_shstrndx
        let old_shstrndx = self.header.e_shstrndx as usize;
        if old_shstrndx < old_to_new.len() {
            self.header.e_shstrndx = old_to_new[old_shstrndx] as u16;
        }

        // Write ELF header
        self.header.try_into_ctx(&mut output[..], self.ctx.le)?;

        // Write program headers
        let ph_start = self.header.e_phoff as usize;
        for (idx, phdr) in self.program_headers.iter().enumerate() {
            let offset = ph_start + idx * phdr_size;
            if offset + phdr_size <= output.len() {
                phdr.clone().try_into_ctx(&mut output[offset..], self.ctx)?;
            }
        }

        // Write section headers at original SHT location
        let sht_offset = self.header.e_shoff as usize;
        for (new_idx, (_, shdr)) in indexed_shdrs.iter().enumerate() {
            let offset = sht_offset + new_idx * sh_size;
            if offset + sh_size <= output.len() {
                shdr.clone().try_into_ctx(&mut output[offset..], self.ctx)?;
            }
        }

        // Update dynamic section entries (DT_STRTAB, DT_SYMTAB, etc.) with new addresses
        self.update_dynamic_addresses(&mut output, &indexed_shdrs)?;

        // Write dynamic section content if it was replaced
        if let Some(content) = self.replaced_sections.get(".dynamic") {
            if let Some((new_offset, _)) = section_new_offsets.get(".dynamic") {
                if let Some(ref entries) = self.dynamic_entries {
                    let entry_size = Dyn::size_with(&self.ctx);
                    for (i, entry) in entries.iter().enumerate() {
                        let pos = new_offset + i * entry_size;
                        if pos + entry_size <= output.len() {
                            entry.clone().try_into_ctx(&mut output[pos..], self.ctx)?;
                        }
                    }
                    // Pad with DT_NULL
                    let null_entry = Dyn {
                        d_tag: goblin::elf::dynamic::DT_NULL,
                        d_val: 0,
                    };
                    let max_entries = content.len() / entry_size;
                    for i in entries.len()..max_entries {
                        let pos = new_offset + i * entry_size;
                        if pos + entry_size <= output.len() {
                            null_entry
                                .clone()
                                .try_into_ctx(&mut output[pos..], self.ctx)?;
                        }
                    }
                }
            }
        } else {
            // Dynamic section not relocated, write to original location
            if let Some(ref entries) = self.dynamic_entries {
                self.write_dynamic_section(&mut output, entries)?;
            }
        }

        Ok(output)
    }

    /// Update dynamic section entries to point to new section locations.
    /// This updates DT_STRTAB, DT_SYMTAB, DT_HASH, DT_GNU_HASH, etc.
    fn update_dynamic_addresses(
        &mut self,
        output: &mut [u8],
        indexed_shdrs: &[(usize, SectionHeader)],
    ) -> error::Result<()> {
        // Find .dynamic section in the sorted list
        let dynamic_offset = indexed_shdrs
            .iter()
            .find(|(_, shdr)| shdr.sh_type == goblin::elf::section_header::SHT_DYNAMIC)
            .map(|(_, shdr)| shdr.sh_offset as usize);

        let dynamic_offset = match dynamic_offset {
            Some(off) => off,
            None => return Ok(()),
        };

        // Pre-compute section addresses and sizes to avoid borrow issues
        use std::collections::HashMap;
        let mut section_addrs: HashMap<String, u64> = HashMap::new();
        let mut section_sizes: HashMap<String, u64> = HashMap::new();
        for (_, shdr) in indexed_shdrs {
            let name = self.get_section_name(shdr);
            section_addrs.insert(name.clone(), shdr.sh_addr);
            section_sizes.insert(name, shdr.sh_size);
        }

        let find_section_addr = |name: &str| -> Option<u64> { section_addrs.get(name).copied() };

        let find_section_size = |name: &str| -> Option<u64> { section_sizes.get(name).copied() };

        // Read and update dynamic entries
        let entry_size = Dyn::size_with(&self.ctx);
        let mut offset = dynamic_offset;

        loop {
            if offset + entry_size > output.len() {
                break;
            }

            let d_tag: u64 = output.pread_with(offset, self.ctx.le)?;
            if d_tag == goblin::elf::dynamic::DT_NULL {
                break;
            }

            let d_val_offset = offset + if self.ctx.container.is_big() { 8 } else { 4 };

            // Update pointers based on dynamic tag type
            match d_tag {
                goblin::elf::dynamic::DT_STRTAB => {
                    if let Some(addr) = find_section_addr(".dynstr") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                goblin::elf::dynamic::DT_STRSZ => {
                    if let Some(size) = find_section_size(".dynstr") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&size.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(size as u32).to_le_bytes());
                        }
                    }
                }
                goblin::elf::dynamic::DT_SYMTAB => {
                    if let Some(addr) = find_section_addr(".dynsym") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                goblin::elf::dynamic::DT_HASH => {
                    if let Some(addr) = find_section_addr(".hash") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                0x6ffffef5 => {
                    // DT_GNU_HASH
                    if let Some(addr) = find_section_addr(".gnu.hash") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                goblin::elf::dynamic::DT_JMPREL => {
                    // Try .rela.plt or .rel.plt
                    let addr = find_section_addr(".rela.plt")
                        .or_else(|| find_section_addr(".rel.plt"));
                    if let Some(addr) = addr {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                goblin::elf::dynamic::DT_REL => {
                    let addr = find_section_addr(".rel.dyn")
                        .or_else(|| find_section_addr(".rel.got"));
                    if let Some(addr) = addr {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                goblin::elf::dynamic::DT_RELA => {
                    if let Some(addr) = find_section_addr(".rela.dyn") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                0x6ffffffe => {
                    // DT_VERNEED
                    if let Some(addr) = find_section_addr(".gnu.version_r") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                0x6ffffff0 => {
                    // DT_VERSYM
                    if let Some(addr) = find_section_addr(".gnu.version") {
                        if self.ctx.container.is_big() {
                            output[d_val_offset..d_val_offset + 8]
                                .copy_from_slice(&addr.to_le_bytes());
                        } else {
                            output[d_val_offset..d_val_offset + 4]
                                .copy_from_slice(&(addr as u32).to_le_bytes());
                        }
                    }
                }
                _ => {}
            }

            offset += entry_size;
        }

        // Also update dynamic entries in memory
        if let Some(ref mut entries) = self.dynamic_entries {
            for entry in entries.iter_mut() {
                match entry.d_tag {
                    goblin::elf::dynamic::DT_STRTAB => {
                        if let Some(addr) = find_section_addr(".dynstr") {
                            entry.d_val = addr;
                        }
                    }
                    goblin::elf::dynamic::DT_STRSZ => {
                        if let Some(size) = find_section_size(".dynstr") {
                            entry.d_val = size;
                        }
                    }
                    goblin::elf::dynamic::DT_SYMTAB => {
                        if let Some(addr) = find_section_addr(".dynsym") {
                            entry.d_val = addr;
                        }
                    }
                    goblin::elf::dynamic::DT_HASH => {
                        if let Some(addr) = find_section_addr(".hash") {
                            entry.d_val = addr;
                        }
                    }
                    0x6ffffef5 => {
                        // DT_GNU_HASH
                        if let Some(addr) = find_section_addr(".gnu.hash") {
                            entry.d_val = addr;
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Write the dynamic section to the output buffer.
    fn write_dynamic_section(&self, output: &mut [u8], entries: &[Dyn]) -> error::Result<()> {
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

        // Pad remaining slots with DT_NULL entries
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::elf::header::{EM_386, EM_ARM, EM_X86_64};

    #[test]
    fn test_round_up() {
        // Test alignment rounding
        assert_eq!(ElfWriter::round_up(0, 4096), 0);
        assert_eq!(ElfWriter::round_up(1, 4096), 4096);
        assert_eq!(ElfWriter::round_up(4095, 4096), 4096);
        assert_eq!(ElfWriter::round_up(4096, 4096), 4096);
        assert_eq!(ElfWriter::round_up(4097, 4096), 8192);

        // Test with alignment 0 (should return value unchanged)
        assert_eq!(ElfWriter::round_up(100, 0), 100);

        // Test with alignment 1
        assert_eq!(ElfWriter::round_up(100, 1), 100);

        // Test 64KB alignment (for AArch64, etc.)
        assert_eq!(ElfWriter::round_up(0x10001, 0x10000), 0x20000);
    }

    #[test]
    fn test_page_sizes_by_architecture() {
        // Verify the page size constants match architecture specifications

        // x86_64 should be 4KB
        assert_eq!(
            page_size_for_machine(EM_X86_64),
            0x1000,
            "x86_64 should use 4KB pages"
        );

        // x86 should be 4KB
        assert_eq!(
            page_size_for_machine(EM_386),
            0x1000,
            "x86 should use 4KB pages"
        );

        // ARM32 should be 4KB
        assert_eq!(
            page_size_for_machine(EM_ARM),
            0x1000,
            "ARM32 should use 4KB pages"
        );

        // AArch64 should be 64KB (conservative choice for compatibility)
        assert_eq!(
            page_size_for_machine(EM_AARCH64),
            0x10000,
            "AArch64 should use 64KB pages"
        );

        // PowerPC64 should be 64KB
        assert_eq!(
            page_size_for_machine(EM_PPC64),
            0x10000,
            "PPC64 should use 64KB pages"
        );

        // MIPS should be 64KB
        assert_eq!(
            page_size_for_machine(EM_MIPS),
            0x10000,
            "MIPS should use 64KB pages"
        );

        // SPARC should be 8KB
        assert_eq!(
            page_size_for_machine(EM_SPARC),
            0x2000,
            "SPARC should use 8KB pages"
        );

        // SPARC64 should be 8KB
        assert_eq!(
            page_size_for_machine(EM_SPARCV9),
            0x2000,
            "SPARC64 should use 8KB pages"
        );
    }

    /// Helper to get page size for a given e_machine value
    fn page_size_for_machine(e_machine: u16) -> usize {
        match e_machine {
            EM_IA_64 | EM_MIPS | EM_PPC | EM_PPC64 | EM_AARCH64 | EM_TILEGX | EM_LOONGARCH => {
                0x10000
            }
            EM_SPARC | EM_SPARCV9 => 0x2000,
            _ => 0x1000,
        }
    }

    #[test]
    fn test_alignment_invariant() {
        // Test the alignment invariant formula: (vaddr - offset) % align == 0

        // Valid alignments
        assert_eq!((0x1000u64.wrapping_sub(0x1000)) % 0x1000, 0);
        assert_eq!((0x2000u64.wrapping_sub(0x1000)) % 0x1000, 0);
        assert_eq!((0x401000u64.wrapping_sub(0x1000)) % 0x1000, 0);

        // Invalid alignments
        assert_ne!((0x1001u64.wrapping_sub(0x1000)) % 0x1000, 0);
        assert_ne!((0x1500u64.wrapping_sub(0x1000)) % 0x1000, 0);
    }
}
