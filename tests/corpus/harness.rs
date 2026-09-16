//! Shared loader for the vendored ELF corpus and its expected-values oracle.
//!
//! The oracle (`corpus.manifest`) is embedded at compile time; the ELF files
//! themselves are read from disk relative to `CARGO_MANIFEST_DIR`.

use std::fs;
use std::path::PathBuf;

const MANIFEST: &str = include_str!("corpus.manifest");

/// One section-header record from the oracle.
pub struct OracleSection {
    pub kind: u32,
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

/// One program-header record from the oracle.
pub struct OracleSegment {
    pub kind: u32,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

/// The expected parse result for one vendored file.
pub struct Entry {
    pub file: String,
    pub class_bits: u8,
    pub little_endian: bool,
    pub machine: u16,
    pub etype: u16,
    pub entry: u64,
    pub phnum: usize,
    pub shnum: usize,
    pub needed: Vec<String>,
    pub sections: Vec<OracleSection>,
    pub segments: Vec<OracleSegment>,
}

impl Entry {
    /// Reads the raw bytes of this entry's vendored ELF file.
    pub fn read_bytes(&self) -> Vec<u8> {
        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "corpus", &self.file]
            .iter()
            .collect();
        fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }
}

fn dec(s: &str) -> u64 {
    s.parse()
        .unwrap_or_else(|e| panic!("bad number {s:?}: {e}"))
}

/// Extracts the value between the first and last double-quote of `s`.
fn quoted(s: &str) -> String {
    let start = s.find('"').expect("quoted name opens");
    let end = s.rfind('"').expect("quoted name closes");
    assert!(end > start, "quoted name is well-formed in {s:?}");
    s[start + 1..end].to_string()
}

/// Parses the embedded manifest into per-file oracle entries.
pub fn corpus() -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;

    for raw in MANIFEST.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "file" => {
                current = Some(Entry {
                    file: rest.to_string(),
                    class_bits: 0,
                    little_endian: true,
                    machine: 0,
                    etype: 0,
                    entry: 0,
                    phnum: 0,
                    shnum: 0,
                    needed: Vec::new(),
                    sections: Vec::new(),
                    segments: Vec::new(),
                });
            }
            "end" => entries.push(current.take().expect("`end` closes an open `file`")),
            other => {
                let e = current.as_mut().expect("record precedes its `file` line");
                match other {
                    "sha256" => {} // provenance only; see PROVENANCE.md
                    "class" => e.class_bits = dec(rest) as u8,
                    "endian" => e.little_endian = rest == "little",
                    "machine" => e.machine = dec(rest) as u16,
                    "type" => e.etype = dec(rest) as u16,
                    "entry" => e.entry = dec(rest),
                    "phnum" => e.phnum = dec(rest) as usize,
                    "shnum" => e.shnum = dec(rest) as usize,
                    "needed" => e.needed.push(rest.to_string()),
                    "sec" => {
                        // sec <idx> <type> <addr> <size> "<name>"
                        let f: Vec<&str> = rest.splitn(5, ' ').collect();
                        e.sections.push(OracleSection {
                            kind: dec(f[1]) as u32,
                            addr: dec(f[2]),
                            size: dec(f[3]),
                            name: quoted(f[4]),
                        });
                    }
                    "seg" => {
                        // seg <idx> <type> <vaddr> <filesz> <memsz>
                        let f: Vec<&str> = rest.split(' ').collect();
                        e.segments.push(OracleSegment {
                            kind: dec(f[1]) as u32,
                            vaddr: dec(f[2]),
                            filesz: dec(f[3]),
                            memsz: dec(f[4]),
                        });
                    }
                    unknown => panic!("unknown manifest key {unknown:?}"),
                }
            }
        }
    }
    assert!(current.is_none(), "final `file` block missing `end`");
    assert!(!entries.is_empty(), "corpus manifest is empty");
    entries
}
