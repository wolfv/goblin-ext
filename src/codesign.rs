//! Ad-hoc code signing for Mach-O binaries
//!
//! This module implements ad-hoc code signing for Mach-O binaries,
//! matching Apple's codesign behavior for linker-signed binaries.
//!
//! # Example
//!
//! ```ignore
//! use goblin_ext::codesign::{adhoc_sign, AdhocSignOptions, Entitlements};
//!
//! // Simple signing with just an identifier
//! let signed = adhoc_sign(data, &AdhocSignOptions::new("com.example.myapp"))?;
//!
//! // With hardened runtime and preserved entitlements
//! let options = AdhocSignOptions::new("com.example.myapp")
//!     .with_hardened_runtime()
//!     .with_entitlements(Entitlements::Preserve);
//! let signed = adhoc_sign(data, &options)?;
//! ```

use alloc::vec::Vec;
use goblin::mach::{
    header::Header,
    load_command::{LC_CODE_SIGNATURE, LC_SEGMENT, LC_SEGMENT_64},
    parse_magic_and_ctx,
};
use goblin::{container, error};

use scroll::{ctx::SizeWith, Pread};

/// Code signature magic numbers and constants
pub mod constants {
    /// Magic number for embedded signature SuperBlob
    pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
    /// Magic number for CodeDirectory blob
    pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
    /// Magic number for embedded entitlements (plist format)
    pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
    /// Magic number for embedded entitlements (DER format)
    pub const CSMAGIC_EMBEDDED_ENTITLEMENTS_DER: u32 = 0xfade7172;
    /// Slot index for CodeDirectory
    pub const CSSLOT_CODEDIRECTORY: u32 = 0;
    /// Slot index for entitlements
    pub const CSSLOT_ENTITLEMENTS: u32 = 5;
    /// Slot index for DER entitlements
    pub const CSSLOT_ENTITLEMENTS_DER: u32 = 7;
    /// SHA-256 hash type
    pub const CS_HASHTYPE_SHA256: u8 = 2;
    /// Ad-hoc signature flag
    pub const CS_ADHOC: u32 = 0x0002;
    /// Hardened runtime flag (--options runtime)
    pub const CS_RUNTIME: u32 = 0x10000;
    /// Linker-signed flag
    pub const CS_LINKER_SIGNED: u32 = 0x20000;
    /// Main binary exec segment flag
    pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
    /// Code signature page size (4KB)
    pub const CS_PAGE_SIZE: usize = 4096;
    /// Code signature page size as log2
    pub const CS_PAGE_SIZE_LOG2: u8 = 12;
    /// CodeDirectory version
    pub const CS_VERSION: u32 = 0x20400;
}

/// How to handle entitlements during ad-hoc signing
#[derive(Debug, Clone, Default)]
pub enum Entitlements<'a> {
    /// No entitlements
    #[default]
    None,
    /// Preserve existing entitlements from the binary's current signature
    Preserve,
    /// Use custom entitlements plist data
    Custom(&'a [u8]),
}

/// Options for ad-hoc code signing
///
/// # Example
/// ```ignore
/// use goblin_ext::codesign::{adhoc_sign, AdhocSignOptions, Entitlements};
///
/// let options = AdhocSignOptions {
///     identifier: "com.example.myapp",
///     hardened_runtime: true,
///     entitlements: Entitlements::Preserve,
/// };
/// let signed = adhoc_sign(binary_data, &options)?;
/// ```
#[derive(Debug, Clone)]
pub struct AdhocSignOptions<'a> {
    /// The identifier to embed in the signature (e.g., "com.example.myapp")
    pub identifier: &'a str,
    /// Enable hardened runtime (equivalent to `codesign --options runtime`)
    pub hardened_runtime: bool,
    /// How to handle entitlements
    pub entitlements: Entitlements<'a>,
}

impl<'a> AdhocSignOptions<'a> {
    /// Create new options with just an identifier (no hardened runtime, no entitlements)
    pub fn new(identifier: &'a str) -> Self {
        Self {
            identifier,
            hardened_runtime: false,
            entitlements: Entitlements::None,
        }
    }

    /// Enable hardened runtime
    pub fn with_hardened_runtime(mut self) -> Self {
        self.hardened_runtime = true;
        self
    }

    /// Set entitlements handling
    pub fn with_entitlements(mut self, entitlements: Entitlements<'a>) -> Self {
        self.entitlements = entitlements;
        self
    }
}

use constants::*;
use sha2::{Digest, Sha256};

/// SuperBlob header for embedded signature
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct SuperBlob {
    magic: u32,
    length: u32,
    count: u32,
}

/// Blob index entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct BlobIndex {
    typ: u32,
    offset: u32,
}

/// CodeDirectory structure (version 0x20400)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct CodeDirectory {
    magic: u32,
    length: u32,
    version: u32,
    flags: u32,
    hash_offset: u32,
    ident_offset: u32,
    n_special_slots: u32,
    n_code_slots: u32,
    code_limit: u32,
    hash_size: u8,
    hash_type: u8,
    _pad1: u8,
    page_size: u8,
    _pad2: u32,
    scatter_offset: u32,
    team_offset: u32,
    _pad3: u32,
    code_limit64: u64,
    exec_seg_base: u64,
    exec_seg_limit: u64,
    exec_seg_flags: u64,
}

impl SuperBlob {
    fn as_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.length.to_be_bytes());
        buf[8..12].copy_from_slice(&self.count.to_be_bytes());
        buf
    }
}

impl BlobIndex {
    fn as_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.typ.to_be_bytes());
        buf[4..8].copy_from_slice(&self.offset.to_be_bytes());
        buf
    }
}

impl CodeDirectory {
    fn as_bytes(&self) -> [u8; 88] {
        let mut buf = [0u8; 88];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.length.to_be_bytes());
        buf[8..12].copy_from_slice(&self.version.to_be_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_be_bytes());
        buf[16..20].copy_from_slice(&self.hash_offset.to_be_bytes());
        buf[20..24].copy_from_slice(&self.ident_offset.to_be_bytes());
        buf[24..28].copy_from_slice(&self.n_special_slots.to_be_bytes());
        buf[28..32].copy_from_slice(&self.n_code_slots.to_be_bytes());
        buf[32..36].copy_from_slice(&self.code_limit.to_be_bytes());
        buf[36] = self.hash_size;
        buf[37] = self.hash_type;
        buf[38] = self._pad1;
        buf[39] = self.page_size;
        buf[40..44].copy_from_slice(&self._pad2.to_be_bytes());
        buf[44..48].copy_from_slice(&self.scatter_offset.to_be_bytes());
        buf[48..52].copy_from_slice(&self.team_offset.to_be_bytes());
        buf[52..56].copy_from_slice(&self._pad3.to_be_bytes());
        buf[56..64].copy_from_slice(&self.code_limit64.to_be_bytes());
        buf[64..72].copy_from_slice(&self.exec_seg_base.to_be_bytes());
        buf[72..80].copy_from_slice(&self.exec_seg_limit.to_be_bytes());
        buf[80..88].copy_from_slice(&self.exec_seg_flags.to_be_bytes());
        buf
    }
}

/// Check if a Mach-O binary has a linker-signed code signature
///
/// This function parses the binary to find the code signature and checks
/// if it has the CS_LINKER_SIGNED flag (0x20000). Returns false if no
/// code signature is found or if it doesn't have the linker-signed flag.
pub fn is_linker_signed(data: &[u8]) -> bool {
    // Parse header
    let (_, ctx_opt) = match parse_magic_and_ctx(data, 0) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let ctx = match ctx_opt {
        Some(c) => c,
        None => return false,
    };
    let header: Header = match data.pread_with(0, ctx) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let header_size = Header::size_with(&ctx);

    // Find LC_CODE_SIGNATURE
    let mut offset = header_size;
    for _ in 0..header.ncmds {
        let cmd: u32 = match data.pread_with(offset, ctx.le) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let cmdsize: u32 = match data.pread_with(offset + 4, ctx.le) {
            Ok(c) => c,
            Err(_) => return false,
        };

        if cmd == LC_CODE_SIGNATURE {
            let dataoff: u32 = match data.pread_with(offset + 8, ctx.le) {
                Ok(d) => d,
                Err(_) => return false,
            };
            let datasize: u32 = match data.pread_with(offset + 12, ctx.le) {
                Ok(d) => d,
                Err(_) => return false,
            };
            return is_linker_signed_internal(data, dataoff as usize, datasize as usize);
        }

        offset += cmdsize as usize;
    }
    false
}

/// Internal helper to check linker-signed flag in code signature
fn is_linker_signed_internal(data: &[u8], codesig_offset: usize, codesig_size: usize) -> bool {
    if codesig_offset + codesig_size > data.len() || codesig_size < 20 {
        return false;
    }

    let sig_data = &data[codesig_offset..codesig_offset + codesig_size];

    // Check SuperBlob magic
    let magic = u32::from_be_bytes([sig_data[0], sig_data[1], sig_data[2], sig_data[3]]);
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return false;
    }

    let count = u32::from_be_bytes([sig_data[8], sig_data[9], sig_data[10], sig_data[11]]) as usize;

    // Find CodeDirectory blob
    for i in 0..count {
        let idx_offset = 12 + i * 8;
        if idx_offset + 8 > sig_data.len() {
            break;
        }
        let blob_type = u32::from_be_bytes([
            sig_data[idx_offset],
            sig_data[idx_offset + 1],
            sig_data[idx_offset + 2],
            sig_data[idx_offset + 3],
        ]);
        let blob_offset = u32::from_be_bytes([
            sig_data[idx_offset + 4],
            sig_data[idx_offset + 5],
            sig_data[idx_offset + 6],
            sig_data[idx_offset + 7],
        ]) as usize;

        if blob_type == CSSLOT_CODEDIRECTORY && blob_offset + 16 <= sig_data.len() {
            // Read CodeDirectory flags at offset 12 from blob start
            let flags = u32::from_be_bytes([
                sig_data[blob_offset + 12],
                sig_data[blob_offset + 13],
                sig_data[blob_offset + 14],
                sig_data[blob_offset + 15],
            ]);
            return (flags & CS_LINKER_SIGNED) != 0;
        }
    }
    false
}

/// Extract entitlements from a Mach-O binary's code signature
///
/// Returns the raw entitlements plist data if present, or None if no entitlements are found.
/// This is useful for implementing `--preserve-metadata=entitlements` functionality.
pub fn extract_entitlements(data: &[u8]) -> Option<Vec<u8>> {
    // Parse header
    let (_, ctx_opt) = parse_magic_and_ctx(data, 0).ok()?;
    let ctx = ctx_opt?;
    let header: Header = data.pread_with(0, ctx).ok()?;
    let header_size = Header::size_with(&ctx);

    // Find LC_CODE_SIGNATURE
    let mut offset = header_size;
    for _ in 0..header.ncmds {
        let cmd: u32 = data.pread_with(offset, ctx.le).ok()?;
        let cmdsize: u32 = data.pread_with(offset + 4, ctx.le).ok()?;

        if cmd == LC_CODE_SIGNATURE {
            let dataoff: u32 = data.pread_with(offset + 8, ctx.le).ok()?;
            let datasize: u32 = data.pread_with(offset + 12, ctx.le).ok()?;
            return extract_entitlements_internal(data, dataoff as usize, datasize as usize);
        }

        offset += cmdsize as usize;
    }
    None
}

/// Internal helper to extract entitlements from code signature blob
fn extract_entitlements_internal(
    data: &[u8],
    codesig_offset: usize,
    codesig_size: usize,
) -> Option<Vec<u8>> {
    if codesig_offset + codesig_size > data.len() || codesig_size < 20 {
        return None;
    }

    let sig_data = &data[codesig_offset..codesig_offset + codesig_size];

    // Check SuperBlob magic
    let magic = u32::from_be_bytes([sig_data[0], sig_data[1], sig_data[2], sig_data[3]]);
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }

    let count = u32::from_be_bytes([sig_data[8], sig_data[9], sig_data[10], sig_data[11]]) as usize;

    // Find entitlements blob
    for i in 0..count {
        let idx_offset = 12 + i * 8;
        if idx_offset + 8 > sig_data.len() {
            break;
        }
        let blob_type = u32::from_be_bytes([
            sig_data[idx_offset],
            sig_data[idx_offset + 1],
            sig_data[idx_offset + 2],
            sig_data[idx_offset + 3],
        ]);
        let blob_offset = u32::from_be_bytes([
            sig_data[idx_offset + 4],
            sig_data[idx_offset + 5],
            sig_data[idx_offset + 6],
            sig_data[idx_offset + 7],
        ]) as usize;

        if blob_type == CSSLOT_ENTITLEMENTS && blob_offset + 8 <= sig_data.len() {
            // Read entitlements blob header
            let blob_magic = u32::from_be_bytes([
                sig_data[blob_offset],
                sig_data[blob_offset + 1],
                sig_data[blob_offset + 2],
                sig_data[blob_offset + 3],
            ]);
            let blob_length = u32::from_be_bytes([
                sig_data[blob_offset + 4],
                sig_data[blob_offset + 5],
                sig_data[blob_offset + 6],
                sig_data[blob_offset + 7],
            ]) as usize;

            if blob_magic == CSMAGIC_EMBEDDED_ENTITLEMENTS
                && blob_offset + blob_length <= sig_data.len()
            {
                // Extract the plist data (after the 8-byte header)
                let plist_data = &sig_data[blob_offset + 8..blob_offset + blob_length];
                return Some(plist_data.to_vec());
            }
        }
    }
    None
}

/// Generate an ad-hoc code signature for a Mach-O binary
///
/// This is a low-level function. Most users should use [`adhoc_sign`] instead.
///
/// # Arguments
/// * `data` - The binary data (will be modified in place)
/// * `identifier` - The identifier string to use in the signature
/// * `codesig_cmd_offset` - Offset of LC_CODE_SIGNATURE load command
/// * `codesig_data_offset` - Offset where code signature data starts
/// * `linkedit_cmd_offset` - Offset of __LINKEDIT segment command
/// * `linkedit_fileoff` - File offset of __LINKEDIT segment
/// * `text_fileoff` - File offset of __TEXT segment
/// * `text_filesize` - File size of __TEXT segment
/// * `is_64bit` - Whether this is a 64-bit binary
/// * `is_executable` - Whether this is a main executable (MH_EXECUTE)
/// * `hardened_runtime` - Whether to enable hardened runtime (CS_RUNTIME flag)
/// * `entitlements` - Optional entitlements plist data to embed
///
/// Returns the new binary data with updated signature
#[allow(clippy::too_many_arguments)]
pub fn generate_adhoc_signature(
    mut data: Vec<u8>,
    identifier: &str,
    codesig_cmd_offset: usize,
    codesig_data_offset: usize,
    linkedit_cmd_offset: usize,
    linkedit_fileoff: u64,
    text_fileoff: u64,
    text_filesize: u64,
    is_64bit: bool,
    is_executable: bool,
    hardened_runtime: bool,
    entitlements: Option<&[u8]>,
) -> error::Result<Vec<u8>> {
    // Calculate sizes
    let id_bytes = identifier.as_bytes();
    let id_len = id_bytes.len() + 1; // Include null terminator
    let n_hashes = codesig_data_offset.div_ceil(CS_PAGE_SIZE);

    // Check if we have entitlements
    let has_entitlements = entitlements.is_some();
    let entitlements_data = entitlements.unwrap_or(&[]);

    // Entitlements blob: 8-byte header (magic + length) + plist data
    let entitlements_blob_size = if has_entitlements {
        8 + entitlements_data.len()
    } else {
        0
    };

    // Number of blobs: CodeDirectory + optional Entitlements
    let blob_count = if has_entitlements { 2 } else { 1 };
    let n_special_slots: u32 = if has_entitlements {
        CSSLOT_ENTITLEMENTS // 5 - we need slots 1-5
    } else {
        0
    };

    let superblob_size = 12; // SuperBlob header
    let blob_indices_size = blob_count * 8; // BlobIndex entries
    let codedir_size = 88; // CodeDirectory header

    // Special slots hashes come BEFORE code hashes in the hash array
    // They are stored at negative indices: slot 1 is at -1, slot 5 is at -5
    let special_hashes_size = n_special_slots as usize * 32;
    let code_hashes_size = n_hashes * 32;

    let hash_offset = codedir_size + id_len + special_hashes_size;
    let codedir_total = codedir_size + id_len + special_hashes_size + code_hashes_size;

    // Calculate total blob content size
    let blob_content_size =
        superblob_size + blob_indices_size + codedir_total + entitlements_blob_size;
    // Apple aligns code signature datasize to 8 bytes
    let padded_sig_size = (blob_content_size + 7) & !7;

    // Calculate blob offsets
    let codedir_offset = superblob_size + blob_indices_size;
    let entitlements_offset = codedir_offset + codedir_total;

    // Build the signature
    let superblob = SuperBlob {
        magic: CSMAGIC_EMBEDDED_SIGNATURE,
        length: blob_content_size as u32,
        count: blob_count as u32,
    };

    // Update LC_CODE_SIGNATURE command FIRST (before hashing)
    let datasize_offset = codesig_cmd_offset + 12;
    data[datasize_offset..datasize_offset + 4]
        .copy_from_slice(&(padded_sig_size as u32).to_le_bytes());

    // Update __LINKEDIT segment filesize FIRST (before hashing)
    let new_linkedit_filesize =
        codesig_data_offset as u64 + padded_sig_size as u64 - linkedit_fileoff;
    if is_64bit {
        let filesize_offset = linkedit_cmd_offset + 48;
        data[filesize_offset..filesize_offset + 8]
            .copy_from_slice(&new_linkedit_filesize.to_le_bytes());
    } else {
        let filesize_offset = linkedit_cmd_offset + 36;
        data[filesize_offset..filesize_offset + 4]
            .copy_from_slice(&(new_linkedit_filesize as u32).to_le_bytes());
    }

    // Build signature blob content
    let mut sig = Vec::with_capacity(padded_sig_size);

    // Write SuperBlob header
    sig.extend_from_slice(&superblob.as_bytes());

    // Write BlobIndex entries
    let codedir_index = BlobIndex {
        typ: CSSLOT_CODEDIRECTORY,
        offset: codedir_offset as u32,
    };
    sig.extend_from_slice(&codedir_index.as_bytes());

    if has_entitlements {
        let ent_index = BlobIndex {
            typ: CSSLOT_ENTITLEMENTS,
            offset: entitlements_offset as u32,
        };
        sig.extend_from_slice(&ent_index.as_bytes());
    }

    // Calculate entitlements hash for special slot (if present)
    let entitlements_hash: [u8; 32] = if has_entitlements {
        // Build the entitlements blob first to hash it
        let mut ent_blob = Vec::with_capacity(entitlements_blob_size);
        ent_blob.extend_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
        ent_blob.extend_from_slice(&(entitlements_blob_size as u32).to_be_bytes());
        ent_blob.extend_from_slice(entitlements_data);

        let mut hasher = Sha256::new();
        hasher.update(&ent_blob);
        hasher.finalize().into()
    } else {
        [0u8; 32]
    };

    // Build CodeDirectory
    let mut flags = CS_ADHOC | CS_LINKER_SIGNED;
    if hardened_runtime {
        flags |= CS_RUNTIME;
    }
    let codedir = CodeDirectory {
        magic: CSMAGIC_CODEDIRECTORY,
        length: codedir_total as u32,
        version: CS_VERSION,
        flags,
        hash_offset: hash_offset as u32,
        ident_offset: codedir_size as u32,
        n_special_slots,
        n_code_slots: n_hashes as u32,
        code_limit: codesig_data_offset as u32,
        hash_size: 32,
        hash_type: CS_HASHTYPE_SHA256,
        _pad1: 0,
        page_size: CS_PAGE_SIZE_LOG2,
        _pad2: 0,
        scatter_offset: 0,
        team_offset: 0,
        _pad3: 0,
        code_limit64: 0,
        exec_seg_base: text_fileoff,
        exec_seg_limit: text_filesize,
        exec_seg_flags: if is_executable {
            CS_EXECSEG_MAIN_BINARY
        } else {
            0
        },
    };

    sig.extend_from_slice(&codedir.as_bytes());

    // Write identifier
    sig.extend_from_slice(id_bytes);
    sig.push(0); // Null terminator

    // Write special slot hashes (in reverse order: slot 5 first, then 4, 3, 2, 1)
    // Special slots are at negative offsets from hash_offset
    if has_entitlements {
        // Slots 1-4 are empty (zeros), slot 5 is entitlements
        for slot in (1..=n_special_slots).rev() {
            if slot == CSSLOT_ENTITLEMENTS {
                sig.extend_from_slice(&entitlements_hash);
            } else {
                sig.extend_from_slice(&[0u8; 32]);
            }
        }
    }

    // Calculate and write page hashes
    let mut hasher = Sha256::new();
    let mut offset = 0;
    while offset < codesig_data_offset {
        let end = core::cmp::min(offset + CS_PAGE_SIZE, codesig_data_offset);
        hasher.update(&data[offset..end]);
        sig.extend_from_slice(&hasher.finalize_reset());
        offset = end;
    }

    // Write entitlements blob (if present)
    if has_entitlements {
        sig.extend_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
        sig.extend_from_slice(&(entitlements_blob_size as u32).to_be_bytes());
        sig.extend_from_slice(entitlements_data);
    }

    // Add padding to reach padded_sig_size
    sig.resize(padded_sig_size, 0);

    // Resize and write signature
    data.resize(codesig_data_offset + padded_sig_size, 0);
    data[codesig_data_offset..].copy_from_slice(&sig);

    Ok(data)
}

/// Sign a Mach-O binary with an ad-hoc signature
///
/// This function handles the complete flow of ad-hoc signing:
/// 1. Parse the binary to find code signature and segment information
/// 2. Generate a new ad-hoc signature with the specified identifier
/// 3. Update the load commands and write the new signature
///
/// # Arguments
/// * `data` - The Mach-O binary data
/// * `options` - Signing options (identifier, hardened runtime, entitlements)
///
/// # Returns
/// The signed binary data, or an error if signing failed
///
/// # Example
/// ```ignore
/// use goblin_ext::codesign::{adhoc_sign, AdhocSignOptions, Entitlements};
///
/// // Simple signing with just an identifier
/// let signed = adhoc_sign(data, &AdhocSignOptions::new("com.example.myapp"))?;
///
/// // With hardened runtime and preserved entitlements
/// let options = AdhocSignOptions::new("com.example.myapp")
///     .with_hardened_runtime()
///     .with_entitlements(Entitlements::Preserve);
/// let signed = adhoc_sign(data, &options)?;
///
/// // With custom entitlements
/// let entitlements_plist = b"<?xml version=\"1.0\"?>...";
/// let options = AdhocSignOptions {
///     identifier: "com.example.myapp",
///     hardened_runtime: true,
///     entitlements: Entitlements::Custom(entitlements_plist),
/// };
/// let signed = adhoc_sign(data, &options)?;
/// ```
pub fn adhoc_sign(data: Vec<u8>, options: &AdhocSignOptions) -> error::Result<Vec<u8>> {
    // Resolve entitlements based on the option
    let entitlements: Option<Vec<u8>> = match &options.entitlements {
        Entitlements::None => None,
        Entitlements::Preserve => extract_entitlements(&data),
        Entitlements::Custom(ent_data) => Some(ent_data.to_vec()),
    };

    // Parse header
    let (_, ctx_opt) = parse_magic_and_ctx(&data, 0)?;
    let ctx = ctx_opt.ok_or(error::Error::Malformed("Invalid Mach-O magic".into()))?;
    let header: Header = data.pread_with(0, ctx)?;
    let is_64bit = ctx.container == container::Container::Big;
    let header_size = Header::size_with(&ctx);

    // Parse load commands to find what we need
    let mut codesig_cmd_offset = None;
    let mut codesig_data_offset = 0usize;
    let mut linkedit_cmd_offset = None;
    let mut linkedit_fileoff = 0u64;
    let mut text_fileoff = 0u64;
    let mut text_filesize = 0u64;

    let mut offset = header_size;
    for _ in 0..header.ncmds {
        let cmd: u32 = data.pread_with(offset, ctx.le)?;
        let cmdsize: u32 = data.pread_with(offset + 4, ctx.le)?;

        if cmd == LC_CODE_SIGNATURE {
            codesig_cmd_offset = Some(offset);
            let dataoff: u32 = data.pread_with(offset + 8, ctx.le)?;
            codesig_data_offset = dataoff as usize;
        } else if cmd == LC_SEGMENT_64 {
            let segname_bytes = &data[offset + 8..offset + 24];
            let segname = core::str::from_utf8(segname_bytes)
                .unwrap_or("")
                .trim_end_matches('\0');

            if segname == "__LINKEDIT" {
                linkedit_cmd_offset = Some(offset);
                linkedit_fileoff = data.pread_with(offset + 32 + 8, ctx.le)?;
            } else if segname == "__TEXT" {
                text_fileoff = data.pread_with(offset + 32 + 8, ctx.le)?;
                text_filesize = data.pread_with(offset + 32 + 16, ctx.le)?;
            }
        } else if cmd == LC_SEGMENT {
            let segname_bytes = &data[offset + 8..offset + 24];
            let segname = core::str::from_utf8(segname_bytes)
                .unwrap_or("")
                .trim_end_matches('\0');

            if segname == "__LINKEDIT" {
                linkedit_cmd_offset = Some(offset);
                linkedit_fileoff = data.pread_with::<u32>(offset + 28 + 4, ctx.le)? as u64;
            } else if segname == "__TEXT" {
                text_fileoff = data.pread_with::<u32>(offset + 28 + 4, ctx.le)? as u64;
                text_filesize = data.pread_with::<u32>(offset + 28 + 8, ctx.le)? as u64;
            }
        }

        offset += cmdsize as usize;
    }

    let codesig_cmd_offset = codesig_cmd_offset
        .ok_or_else(|| error::Error::Malformed("No LC_CODE_SIGNATURE found".into()))?;
    let linkedit_cmd_offset = linkedit_cmd_offset
        .ok_or_else(|| error::Error::Malformed("No __LINKEDIT segment found".into()))?;

    // Check if this is a main executable (MH_EXECUTE = 2)
    let is_executable = header.filetype == 2;

    generate_adhoc_signature(
        data,
        options.identifier,
        codesig_cmd_offset,
        codesig_data_offset,
        linkedit_cmd_offset,
        linkedit_fileoff,
        text_fileoff,
        text_filesize,
        is_64bit,
        is_executable,
        options.hardened_runtime,
        entitlements.as_deref(),
    )
}
