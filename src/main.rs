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

/// Parse `buf` as an object file, iterate over the sections contained within it, and
/// return a `Vec` containing a (name, size, Section) tuple for each section.
fn sections(buf: &[u8]) -> Result<Vec<(&str, u64, Section)>, Error> {
    Ok(match Object::parse(buf)? {
        Object::Elf(elf) => {
            elf.section_headers.iter().filter_map(|sec| {
                elf.shdr_strtab.get(sec.sh_name)
                    .and_then(|res| res.ok())
                    .map(|name| (name, sec.sh_size, if !sec.is_alloc() {
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
        Object::PE(_pe) => {
            unimplemented!()
        },
        Object::Mach(_mach) => {
            unimplemented!()
        },
        _ => bail!("Unhandled file type!"),
    })
}

fn main() -> Result<(), Error> {
    let path = env::args_os().nth(1).unwrap();
    let f = File::open(&path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let mut map: BTreeMap<Section, BTreeMap<&str, u64>> = BTreeMap::new();
    for (name, size, section) in sections(&buf)? {
        map.entry(section)
            .or_insert_with(|| BTreeMap::<&str, u64>::new()).insert(name, size);
    }
    let mut stdout = io::stdout();
    serde_json::to_writer_pretty(&mut stdout, &map)?;
    Ok(())
}
