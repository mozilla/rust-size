#[macro_use]
extern crate failure;
extern crate goblin;
extern crate memmap;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use failure::Error;
use goblin::elf::section_header::SHT_NOBITS;
use goblin::mach::constants::SECT_BSS;
use goblin::mach::constants::SEG_DATA;
use goblin::mach::constants::SEG_TEXT;
use goblin::mach::Mach;
use goblin::pe::section_table::IMAGE_SCN_MEM_READ;
use goblin::pe::section_table::IMAGE_SCN_MEM_WRITE;
use goblin::Object;
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io;

/// Possible types of object file sections.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
enum Section {
    /// Executable code.
    Text,
    /// Non-writable data.
    Data,
    /// Zero-filled data.
    Bss,
    /// Non-allocated section.
    Other,
}

/// Maps a Mach-O section name to it's ELF counterpart if possible.
///
/// |---------------------------------------|
/// |     Mach-O       |         ELF        |
/// |------------------|--------------------|
/// | __TEXT.__text    | .text              |
/// | __TEXT.__const   | .rodata            |
/// | __TEXT.__cstring | .cstring (.rodata) |
/// | __DATA.__data    | .data              |
/// | __DATA.__const   | .data.rel.ro       |
/// |---------------------------------------|
fn map_mach_name(seg_name: &str, sec_name: &str) -> String {
    let mapped = match seg_name {
        SEG_TEXT => match sec_name {
            "__text" => ".text",
            "__const" => ".rodata",
            "__cstring" => ".cstring", // Not really an ELF name
            _ => sec_name
        },
        SEG_DATA => match sec_name {
            "__data" => ".data",
            "__const" => ".data.rel.ro",
            "__bss" => ".bss",
            _ => sec_name
        },
        _ => sec_name
    };

    mapped.to_string()
}

/// Parse `buf` as an object file, iterate over the sections contained within it, and
/// return a `Vec` containing a (name, size, Section) tuple for each section.
fn sections(buf: &[u8]) -> Result<Vec<(String, u64, Section)>, Error> {
    Ok(match Object::parse(buf)? {
        Object::Elf(elf) => {
            elf.section_headers.iter().filter_map(|sec| {
                elf.shdr_strtab.get(sec.sh_name)
                    .and_then(|res| res.ok())
                    .map(|name| (name.to_string(), sec.sh_size, if !sec.is_alloc() {
                        Section::Other
                    } else if sec.is_executable() || !sec.is_writable() {
                        Section::Text
                    } else if sec.sh_type != SHT_NOBITS {
                        Section::Data
                    } else {
                        Section::Bss
                    }))
            }).collect()
        },
        Object::PE(pe) => {
            let mut bss: u64 = 0;
            let mut vec: Vec<(String, u64, Section)> = pe.sections.iter().map(|sec| {
                let mut size = sec.virtual_size as u64;
                let sec_type = if (sec.characteristics & IMAGE_SCN_MEM_WRITE) == 0 {
                    Section::Text
                } else if (sec.characteristics & IMAGE_SCN_MEM_READ) != 0 {
                    // My understanding is that bss is "hidden" in the portion
                    // of the data section that is allocated in memory but does
                    // not correspond to the on disk size.
                    let delta = if sec.virtual_size > sec.size_of_raw_data {
                        sec.virtual_size - sec.size_of_raw_data
                    } else {
                        0
                    };

                    bss += delta as u64;

                    // Since we're splitting out bss we need to use the raw
                    // size instead.
                    size = sec.size_of_raw_data as u64;

                    Section::Data
                } else {
                    Section::Other
                };

               (sec.name().unwrap().to_string(), size, sec_type)
            }).collect();

            if pe.header.optional_header.is_some() {
                let hdr = pe.header.optional_header.unwrap();
                let size = hdr.standard_fields.size_of_uninitialized_data;

                // In theory the optional header can hold ths size of BSS aka
                // uninitialized data. In practice this seems to be zero.
                if size != 0 {
                    vec.push((".bss".to_string(), size, Section::Bss));
                } else {
                    vec.push((".bss".to_string(), bss, Section::Bss));
                }
            }

            vec
        },
        Object::Mach(m) => {
            match m {
                Mach::Fat(_fat) => {
                    unimplemented!()
                },
                Mach::Binary(mach) => {
                    // `sections` is actually an iterator of iterators.
                    let sections_itr = mach.segments.sections();
                    sections_itr.flat_map(|i| i).filter_map(|s| s.ok()).map(|(sec, _data)| {
                        let name = sec.name().unwrap();
                        let seg = sec.segname().unwrap();
                        (map_mach_name(seg, name), sec.size, if name == SECT_BSS {
                            Section::Bss
                        } else if seg == SEG_DATA {
                            Section::Data
                        } else if seg == SEG_TEXT {
                            Section::Text
                        } else {
                            Section::Other
                        })
                    }).collect()
                }
            }
        },
        _ => bail!("Unhandled file type!"),
    })
}

fn real_main() -> Result<(), Error> {
    let path = env::args_os().nth(1).unwrap();
    let f = File::open(&path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let mut map: BTreeMap<Section, BTreeMap<String, u64>> = BTreeMap::new();
    for (name, size, section) in sections(&buf)? {
        map.entry(section)
            .or_insert_with(|| BTreeMap::<String, u64>::new()).insert(name, size);
    }
    let mut stdout = io::stdout();
    serde_json::to_writer_pretty(&mut stdout, &map)?;
    Ok(())
}

fn main() {
    match real_main() {
        Ok(_) => {},
        Err(err) => println!("Error: {:?}", err),
    }
}
