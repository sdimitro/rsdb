use anyhow::{Context, Result};
use clap::Parser;
use derive_more::Debug;
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use goblin::elf::{Elf, ProgramHeader};
use memmap2::Mmap;
use object::{Object, ObjectSection};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::rc::Rc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(value_name = "binary file")]
    binary_file_path: String,

    #[arg(value_name = "core file")]
    core_file_path: String,
}

#[derive(Debug)]
struct MemoryMappedObjectFile<'a> {
    file: object::File<'a>,

    // This is the memory map that's indirectly used by `file` but we need to
    // make sure its lifetime is the same as this struct so we save it as a
    // member. The use of this member directly should be rare.
    mmap: Rc<Mmap>,
}

impl<'a> MemoryMappedObjectFile<'a> {
    fn new(path: &Path) -> Result<Self> {
        let f =
            File::open(path).with_context(|| format!("Failed to open file: {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&f) }
            .with_context(|| format!("Failed to memory map file: {}", path.display()))?;

        // We use Rc to to share ownership of the memory-mapped data. This ensures that
        // the data will not be dropped as long as there are any references to it.
        let mmap_rc = Rc::new(mmap);

        // We create a reference (with lifetime 'a) to the data inside the Rc.
        // This is safe because the data will live as long as the Rc exists,
        // and the Rc will be stored in the struct, ensuring the data will live
        // as long as its reference the reference. Using transmute is unsafe
        // because it bypasses Rust's lifetime checks, but it is safe in this
        // context because the Rc ensures the data will live as long as needed.
        let mmap_ref: &'a [u8] = unsafe { std::mem::transmute(&**mmap_rc) };

        let file = object::File::parse(mmap_ref)
            .with_context(|| format!("Failed to parse file: {}", path.display()))?;

        Ok(MemoryMappedObjectFile {
            file,
            mmap: mmap_rc,
        })
    }
}

type VirtualAddr = usize;

// Assumes just ELF cores for now
#[derive(Debug)]
struct MemorySegment {
    virtual_address: VirtualAddr,
    virtual_size: usize,

    _physical_address: usize,
    physical_size: usize,

    _core_offset: usize,
    _flags: u32,
    _alignment: usize,

    #[debug(skip)]
    contents: Vec<u8>, // XXX: may not be needed since we have the mmap
}

impl MemorySegment {
    fn new(program_header: &ProgramHeader, core: &MemoryMappedObjectFile) -> Self {
        let core_offset = program_header.p_offset as usize;
        let physical_size = program_header.p_filesz as usize;
        let segment_end = core_offset + physical_size;

        // XXX: need usize conversion instead of `as`
        MemorySegment {
            virtual_address: program_header.p_vaddr as usize,
            virtual_size: program_header.p_memsz as usize,
            _physical_address: program_header.p_paddr as usize,
            physical_size,
            _core_offset: core_offset,
            _flags: program_header.p_flags,
            _alignment: program_header.p_align as usize,
            contents: core.mmap[core_offset..segment_end].to_vec(),
        }
    }
}

#[derive(Debug)]
struct CoreDumpDebugger<'a> {
    #[debug(skip)]
    dwarf_info: Dwarf<EndianSlice<'a, RunTimeEndian>>,
    #[debug(skip)]
    _core: MemoryMappedObjectFile<'a>,
    #[debug(skip)]
    _executable: MemoryMappedObjectFile<'a>,

    // Virtual Address to Memory Content mapping
    // XXX: use a sorted structure for faster lookup
    memory_map: HashMap<VirtualAddr, MemorySegment>,

    // Register values from core dump
    registers: HashMap<String, u64>,
}

impl<'a> CoreDumpDebugger<'a> {
    fn new(executable_path: &Path, core_path: &Path) -> Result<Self> {
        // Load ELF files
        let executable = MemoryMappedObjectFile::new(executable_path)?;
        let core = MemoryMappedObjectFile::new(core_path)?;

        // Load DWARF information
        let endian = if executable.file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        // Load DWARF sections
        let load_section = |id: gimli::SectionId| -> Result<EndianSlice<'a, RunTimeEndian>> {
            let section = executable
                .file
                .section_by_name(id.name())
                .unwrap_or_else(|| executable.file.section_by_name("").unwrap());
            let data = section
                .data()
                .map_err(anyhow::Error::from)
                .context("Failed to get section data")?;
            Ok(EndianSlice::new(data, endian))
        };

        // Create DWARF context
        let dwarf = Dwarf::load(&load_section).context("Failed to load DWARF info")?;

        let core_elf = Elf::parse(&core.mmap).context("Failed to parse core dump as ELF")?;

        // Create memory map from core dump segments
        let mut memory_map = HashMap::new();
        for program_header in &core_elf.program_headers {
            if program_header.p_type == goblin::elf::program_header::PT_LOAD {
                let memory_segment = MemorySegment::new(program_header, &core);
                memory_map.insert(memory_segment.virtual_address, memory_segment);
            }
        }

        // Extract registers from NT_PRSTATUS note if available
        let mut registers = HashMap::new();
        for note_result in core_elf
            .iter_note_headers(&core.mmap)
            .context("Failed to iterate over core dump notes")?
        {
            let note = note_result.context("Failed to parse note header")?;
            if note.n_type == goblin::elf::note::NT_PRSTATUS {
                let data = note.desc;
                if data.len() >= 16 {
                    // XXX: why more than 16?
                    registers.insert(
                        "rax".to_string(),
                        u64::from_le_bytes(
                            data[0..8]
                                .try_into()
                                .context("Failed to read RAX register")?,
                        ),
                    );
                    registers.insert(
                        "rbx".to_string(),
                        u64::from_le_bytes(
                            data[8..16]
                                .try_into()
                                .context("Failed to read RBX register")?,
                        ),
                    );
                }
            }
        }

        Ok(CoreDumpDebugger {
            dwarf_info: dwarf,
            _core: core,
            _executable: executable,
            memory_map,
            registers,
        })
    }

    fn read_memory(&self, virtual_address: usize, size: usize) -> Option<&[u8]> {
        // Find the segment containing the address
        for (segment_base_addr, segment) in &self.memory_map {
            if virtual_address < *segment_base_addr {
                continue;
            }
            let offset = virtual_address - *segment_base_addr;
            if offset < segment.virtual_size {
                let end_offset = (offset + size).min(segment.physical_size);
                return Some(&segment.contents[offset..end_offset]);
            }
        }
        None
    }

    pub fn get_type_info(&self, type_name: &str) -> Result<String> {
        let mut type_info = String::new();

        // Iterate through all compilation units
        let mut iter = self.dwarf_info.units();
        while let Some(header) = iter.next().context("Failed to iterate compilation units")? {
            let unit = self
                .dwarf_info
                .unit(header)
                .context("Failed to get compilation unit")?;

            // Iterate through the Debugging Information Entries (DIEs)
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().context("Failed to iterate DIEs")? {
                // Look for DW_TAG_structure_type or DW_TAG_class_type
                if entry.tag() == gimli::constants::DW_TAG_structure_type
                    || entry.tag() == gimli::constants::DW_TAG_class_type
                {
                    // Get the type name
                    if let Some(name_attr) = entry
                        .attr_value(gimli::constants::DW_AT_name)
                        .context("Failed to get type name attribute")?
                    {
                        if let Some(name) = name_attr.string_value(&self.dwarf_info.debug_str) {
                            if name
                                .to_string()
                                .context("Failed to convert name to string")?
                                == type_name
                            {
                                // Found the type, now collect its information
                                type_info.push_str(&format!("Type: {}\n", type_name));

                                // Get type size
                                if let Some(size_attr) = entry
                                    .attr_value(gimli::constants::DW_AT_byte_size)
                                    .context("Failed to get type size attribute")?
                                {
                                    if let Some(size) = size_attr.udata_value() {
                                        type_info.push_str(&format!("Size: {} bytes\n", size));
                                    }
                                }

                                // Get members/fields
                                type_info.push_str("Members:\n");
                                let mut members = entries.clone();
                                while let Some((depth, member)) = members
                                    .next_dfs()
                                    .context("Failed to iterate member DIEs")?
                                {
                                    if depth < 0 {
                                        break;
                                    }

                                    if member.tag() == gimli::constants::DW_TAG_member {
                                        if let Some(name_attr) = member
                                            .attr_value(gimli::constants::DW_AT_name)
                                            .context("Failed to get member name attribute")?
                                        {
                                            if let Some(name) =
                                                name_attr.string_value(&self.dwarf_info.debug_str)
                                            {
                                                type_info.push_str(&format!(
                                                    "  - {}\n",
                                                    name.to_string().context(
                                                        "Failed to convert member name to string"
                                                    )?
                                                ));
                                            }
                                        }
                                    }
                                }
                                return Ok(type_info);
                            }
                        }
                    }
                }
            }
        }
        Ok(format!(
            "Type '{}' not found in debug information",
            type_name
        ))
    }

    pub fn get_register(&self, register_name: &str) -> Option<u64> {
        self.registers.get(register_name).copied()
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dbg = CoreDumpDebugger::new(
        Path::new(&args.binary_file_path),
        Path::new(&args.core_file_path),
    )?;
    println!("{:#?}", dbg);

    // None
    println!("{:?}", dbg.read_memory(0x400000, 16));

    // (gdb) p HELP
    // $1 = 0xc7bb2fac08d0 "EXAMPLE STRING"
    let help_constant = dbg.read_memory(0xc7bb2fac08d0, 14);
    let help_str = std::str::from_utf8(dbg.read_memory(0xc7bb2fac08d0, 14).unwrap())?;
    println!("{:?} -> {}", help_constant, help_str); // Some([69, 88, 65, 77, 80, 76, 69, 32, 83, 84, 82, 73, 78, 71]) -> EXAMPLE STRING

    // Type: mtype
    // Size: 16 bytes
    // Members:
    //   - m_x
    //   - m_long
    println!("\n{}", dbg.get_type_info("mtype")?);
    println!("\nRAX: {:?}", dbg.get_register("rax")); // -> RAX: Some(6)

    Ok(())
}
