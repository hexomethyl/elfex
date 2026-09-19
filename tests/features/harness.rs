//! Shared loader for the compiled ELF feature corpus and its oracle.
//!
//! The oracle (`features.manifest`) is embedded at compile time; the ELF files
//! themselves are read from disk relative to `CARGO_MANIFEST_DIR`.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

const MANIFEST: &str = include_str!("features.manifest");

/// One program-header record from the oracle.
pub struct OracleSegment {
    pub kind: u32,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
    pub align: u64,
}

/// One section-header record from the oracle.
pub struct OracleSection {
    pub kind: u32,
    pub addr: u64,
    pub size: u64,
    pub flags: u64,
    pub entsize: u64,
    pub name: String,
}

/// One relocation table's identity, form, and entry count.
pub struct OracleRelTable {
    pub name: String,
    pub is_rela: bool,
    pub count: usize,
}

/// The first entry of one relocation table, pinning the field decode.
pub struct OracleRelFirst {
    pub name: String,
    pub offset: u64,
    pub symbol: u32,
    pub r_type: u32,
    /// `None` for `REL` tables, which carry no explicit addend.
    pub addend: Option<i64>,
}

/// One fully decoded, pinned symbol.
pub struct OracleSymbol {
    /// Either `symtab` or `dynsym`.
    pub table: String,
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub bind: u8,
    pub sym_type: u8,
    pub visibility: u8,
    pub shndx: u16,
}

/// One note record from a `PT_NOTE` segment.
pub struct OracleNote {
    pub name: String,
    pub note_type: u32,
    pub descsz: usize,
}

/// A per-table histogram bucket: `(table, key, count)`.
pub type Bucket = (String, u8, usize);

/// The expected parse result for one compiled fixture.
pub struct Entry {
    pub file: String,
    pub sha256: String,
    pub class_bits: u8,
    pub little_endian: bool,
    pub osabi: u8,
    pub etype: u16,
    pub machine: u16,
    pub entry: u64,
    pub phnum: usize,
    pub shnum: usize,
    pub image_base: u64,
    pub image_span: u64,
    pub segments: Vec<OracleSegment>,
    pub sections: Vec<OracleSection>,
    pub dynamic: Vec<(u64, u64)>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub runpath: Option<String>,
    pub rpath: Option<String>,
    /// `(template_vaddr, file_size, mem_size, align)` of `PT_TLS`.
    pub tls: Option<(u64, u64, u64, u64)>,
    pub notes: Vec<OracleNote>,
    pub build_id: Option<String>,
    pub rel_tables: Vec<OracleRelTable>,
    /// Aggregate `(r_type, count)` across every relocation table.
    pub rel_types: Vec<(u32, usize)>,
    pub rel_first: Vec<OracleRelFirst>,
    pub symtab_count: usize,
    pub dynsym_count: usize,
    pub sym_binds: Vec<Bucket>,
    pub sym_types: Vec<Bucket>,
    pub sym_visibilities: Vec<Bucket>,
    pub symbols: Vec<OracleSymbol>,
}

impl Entry {
    /// Reads the fixture's bytes from disk.
    pub fn read_bytes(&self) -> Vec<u8> {
        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "features", &self.file]
            .iter()
            .collect();
        fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// Returns the named section record, if the fixture has one.
    pub fn section(&self, name: &str) -> Option<&OracleSection> {
        self.sections.iter().find(|section| section.name == name)
    }

    /// Returns the pinned symbol with `name` from `table`.
    pub fn symbol(&self, table: &str, name: &str) -> Option<&OracleSymbol> {
        self.symbols
            .iter()
            .find(|symbol| symbol.table == table && symbol.name == name)
    }

    /// Returns the aggregate count recorded for one relocation type.
    pub fn rel_type_count(&self, r_type: u32) -> usize {
        self.rel_types
            .iter()
            .find(|(key, _)| *key == r_type)
            .map_or(0, |(_, count)| *count)
    }

    /// Tests whether the fixture declares one dynamic tag.
    pub fn has_dyn_tag(&self, tag: u64) -> bool {
        self.dynamic.iter().any(|(key, _)| *key == tag)
    }
}

fn dec(text: &str) -> u64 {
    text.parse().unwrap_or_else(|_| panic!("not a number: {text:?}"))
}

/// Splits a record into the tokens before a quoted field, the field, and the
/// tokens after it.
fn split_quoted(line: &str) -> (Vec<&str>, String, Vec<&str>) {
    let first = line.find('"').unwrap_or_else(|| panic!("no quote: {line:?}"));
    let last = line.rfind('"').unwrap_or_else(|| panic!("no quote: {line:?}"));
    (
        line[..first].split_whitespace().collect(),
        line[first + 1..last].to_string(),
        line[last + 1..].split_whitespace().collect(),
    )
}

fn blank() -> Entry {
    Entry {
        file: String::new(),
        sha256: String::new(),
        class_bits: 0,
        little_endian: true,
        osabi: 0,
        etype: 0,
        machine: 0,
        entry: 0,
        phnum: 0,
        shnum: 0,
        image_base: 0,
        image_span: 0,
        segments: Vec::new(),
        sections: Vec::new(),
        dynamic: Vec::new(),
        needed: Vec::new(),
        soname: None,
        runpath: None,
        rpath: None,
        tls: None,
        notes: Vec::new(),
        build_id: None,
        rel_tables: Vec::new(),
        rel_types: Vec::new(),
        rel_first: Vec::new(),
        symtab_count: 0,
        dynsym_count: 0,
        sym_binds: Vec::new(),
        sym_types: Vec::new(),
        sym_visibilities: Vec::new(),
        symbols: Vec::new(),
    }
}

/// Parses the embedded manifest into per-fixture oracle entries.
pub fn corpus() -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut current = blank();
    let mut started = false;

    for line in MANIFEST.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or_default();

        if key == "file" {
            if started {
                entries.push(core::mem::replace(&mut current, blank()));
            }
            started = true;
            current.file = parts.next().unwrap_or_default().to_string();
            continue;
        }

        match key {
            "sha256" => current.sha256 = parts.next().unwrap_or_default().to_string(),
            "class" => {
                current.class_bits = u8::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "endian" => current.little_endian = parts.next().unwrap_or_default() == "little",
            "osabi" => {
                current.osabi = u8::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "type" => {
                current.etype = u16::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "machine" => {
                current.machine = u16::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "entry" => current.entry = dec(parts.next().unwrap_or_default()),
            "phnum" => {
                current.phnum = usize::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "shnum" => {
                current.shnum = usize::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "imagebase" => current.image_base = dec(parts.next().unwrap_or_default()),
            "imagespan" => current.image_span = dec(parts.next().unwrap_or_default()),
            "buildid" => current.build_id = Some(parts.next().unwrap_or_default().to_string()),
            "seg" => {
                let fields: Vec<u64> = parts.map(dec).collect();
                current.segments.push(OracleSegment {
                    kind: u32::try_from(fields[1]).unwrap(),
                    vaddr: fields[2],
                    filesz: fields[3],
                    memsz: fields[4],
                    flags: u32::try_from(fields[5]).unwrap(),
                    align: fields[6],
                });
            }
            "dyn" => {
                let fields: Vec<u64> = parts.map(dec).collect();
                current.dynamic.push((fields[0], fields[1]));
            }
            "reltype" => {
                let fields: Vec<u64> = parts.map(dec).collect();
                current
                    .rel_types
                    .push((u32::try_from(fields[0]).unwrap(), usize::try_from(fields[1]).unwrap()));
            }
            "tls" => {
                let fields: Vec<u64> = parts.map(dec).collect();
                current.tls = Some((fields[0], fields[1], fields[2], fields[3]));
            }
            "symtab" => {
                current.symtab_count =
                    usize::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "dynsym" => {
                current.dynsym_count =
                    usize::try_from(dec(parts.next().unwrap_or_default())).unwrap();
            }
            "symbind" | "symtype" | "symvis" => {
                let table = parts.next().unwrap_or_default().to_string();
                let fields: Vec<u64> = parts.map(dec).collect();
                let bucket = (
                    table,
                    u8::try_from(fields[0]).unwrap(),
                    usize::try_from(fields[1]).unwrap(),
                );
                match key {
                    "symbind" => current.sym_binds.push(bucket),
                    "symtype" => current.sym_types.push(bucket),
                    _ => current.sym_visibilities.push(bucket),
                }
            }
            "sec" => {
                let (head, name, _) = split_quoted(line);
                let fields: Vec<u64> = head[1..].iter().copied().map(dec).collect();
                current.sections.push(OracleSection {
                    kind: u32::try_from(fields[1]).unwrap(),
                    addr: fields[2],
                    size: fields[3],
                    flags: fields[4],
                    entsize: fields[5],
                    name,
                });
            }
            "needed" => {
                let (_, name, _) = split_quoted(line);
                current.needed.push(name);
            }
            "soname" => current.soname = Some(split_quoted(line).1),
            "runpath" => current.runpath = Some(split_quoted(line).1),
            "rpath" => current.rpath = Some(split_quoted(line).1),
            "note" => {
                let (_, name, tail) = split_quoted(line);
                current.notes.push(OracleNote {
                    name,
                    note_type: u32::try_from(dec(tail[0])).unwrap(),
                    descsz: usize::try_from(dec(tail[1])).unwrap(),
                });
            }
            "reltab" => {
                let (_, name, tail) = split_quoted(line);
                current.rel_tables.push(OracleRelTable {
                    name,
                    is_rela: tail[0] == "1",
                    count: usize::try_from(dec(tail[1])).unwrap(),
                });
            }
            "rel0" => {
                let (_, name, tail) = split_quoted(line);
                current.rel_first.push(OracleRelFirst {
                    name,
                    offset: dec(tail[0]),
                    symbol: u32::try_from(dec(tail[1])).unwrap(),
                    r_type: u32::try_from(dec(tail[2])).unwrap(),
                    addend: if tail[3] == "none" {
                        None
                    } else {
                        Some(tail[3].parse().expect("a signed addend"))
                    },
                });
            }
            "sym" => {
                let (head, name, tail) = split_quoted(line);
                let fields: Vec<u64> = tail.iter().copied().map(dec).collect();
                current.symbols.push(OracleSymbol {
                    table: head[1].to_string(),
                    name,
                    value: fields[0],
                    size: fields[1],
                    bind: u8::try_from(fields[2]).unwrap(),
                    sym_type: u8::try_from(fields[3]).unwrap(),
                    visibility: u8::try_from(fields[4]).unwrap(),
                    shndx: u16::try_from(fields[5]).unwrap(),
                });
            }
            other => panic!("unknown manifest record: {other:?}"),
        }
    }

    if started {
        entries.push(current);
    }
    entries
}

/// Returns the one fixture with `name`, or panics naming what is available.
pub fn fixture(name: &str) -> Entry {
    let wanted = format!("bin/{name}");
    corpus()
        .into_iter()
        .find(|entry| entry.file == wanted)
        .unwrap_or_else(|| panic!("no fixture named {name:?} in features.manifest"))
}
