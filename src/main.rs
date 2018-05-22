#[macro_use]
extern crate failure;
extern crate goblin;
extern crate memmap;

use failure::Error;
use goblin::elf::section_header::SHT_NOBITS;
use goblin::Object;
use std::env;
use std::fs::File;

enum Section {
    Text,
    Data,
    Bss,
    Other,
}

fn sections(buf: &[u8]) -> Result<Vec<(Section, u64)>, Error> {
    Ok(match Object::parse(buf)? {
        Object::Elf(elf) => {
            elf.section_headers.iter().map(|sec| {
                (if !sec.is_alloc() {
                    Section::Other
                } else if sec.is_executable() || !sec.is_writable() {
                    Section::Text
                } else if sec.sh_type != SHT_NOBITS {
                    Section::Data
                } else {
                    Section::Bss
                }, sec.sh_size)
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
    let mut text = 0;
    let mut data = 0;
    let mut bss = 0;
    for (section, size) in sections(&buf)? {
        match section {
            Section::Text => text += size,
            Section::Data  => data += size,
            Section::Bss => bss += size,
            Section::Other => {}
        }
    }
    println!("   text\t   data\t    bss\t    dec\t    hex\tfilename");
    let total = text + data + bss;
    println!("{:7}\t{:7}\t{:7}\t{:7}\t{:7x}\t{}", text, data, bss, total, total, path.to_string_lossy());
    Ok(())
}
