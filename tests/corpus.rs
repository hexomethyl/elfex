//! Cross-architecture ELF corpus tests.
//!
//! These tests drive `elfex` over a wide set of real-world ELF objects (many
//! architectures, both classes, both byte orders, and the `EXEC`/`DYN`/`REL`/
//! `CORE` object types) and assert its parse against an independent oracle. See
//! `tests/corpus/PROVENANCE.md` for the corpus sources and how the oracle is
//! generated.

#[path = "corpus/harness.rs"]
mod harness;

use elfex::{ElfFile, Endian};
use harness::{Entry, corpus};

fn parse(entry: &Entry) -> ElfFile {
    let bytes = entry.read_bytes();
    ElfFile::parse(&bytes).unwrap_or_else(|e| panic!("{}: parse failed: {e:?}", entry.file))
}

/// Item 1 — every vendored file parses and its ELF header decodes to the
/// oracle's class, byte order, machine, type, entry point, and table counts.
#[test]
fn header_and_counts_match_oracle() {
    for entry in corpus() {
        let file = parse(&entry);
        let img = file.image();
        let name = &entry.file;

        let bits: u8 = if img.is_64bit() { 64 } else { 32 };
        assert_eq!(bits, entry.class_bits, "{name}: class");

        let little = img.ident().data == Endian::Little;
        assert_eq!(little, entry.little_endian, "{name}: byte order");
        assert_eq!(img.machine().value(), entry.machine, "{name}: e_machine");
        assert_eq!(img.header().r#type.to_u16(), entry.etype, "{name}: e_type");
        assert_eq!(img.entry_point(), entry.entry, "{name}: e_entry");
        assert_eq!(img.segments().len(), entry.phnum, "{name}: e_phnum");
        assert_eq!(img.sections().len(), entry.shnum, "{name}: e_shnum");
    }
}

/// Item 3 — the parsed section and program header tables match the oracle field
/// for field, in table order.
#[test]
fn section_and_segment_tables_match_oracle() {
    for entry in corpus() {
        let file = parse(&entry);
        let img = file.image();
        let name = &entry.file;

        for (i, want) in entry.sections.iter().enumerate() {
            let got = &img.sections()[i];
            assert_eq!(got.header.r#type.0, want.kind, "{name}: sec[{i}] sh_type");
            assert_eq!(got.header.addr, want.addr, "{name}: sec[{i}] sh_addr");
            assert_eq!(got.header.size, want.size, "{name}: sec[{i}] sh_size");
            assert_eq!(got.name, want.name, "{name}: sec[{i}] name");
        }

        for (i, want) in entry.segments.iter().enumerate() {
            let got = &img.segments()[i];
            assert_eq!(got.header.r#type.0, want.kind, "{name}: seg[{i}] p_type");
            assert_eq!(got.header.vaddr, want.vaddr, "{name}: seg[{i}] p_vaddr");
            assert_eq!(got.header.filesz, want.filesz, "{name}: seg[{i}] p_filesz");
            assert_eq!(got.header.memsz, want.memsz, "{name}: seg[{i}] p_memsz");
        }
    }
}

/// Item 3 — `DT_NEEDED` resolution through `.dynstr` matches the oracle.
#[test]
fn needed_libraries_match_oracle() {
    for entry in corpus() {
        let file = parse(&entry);
        let got = file
            .needed_libraries()
            .unwrap_or_else(|e| panic!("{}: needed_libraries: {e:?}", entry.file));
        assert_eq!(got, entry.needed, "{}: DT_NEEDED", entry.file);
    }
}

/// Item 1 — the derived-table accessors decode every file without error. Their
/// exact contents are architecture-specific; this guards against panics and
/// decode failures across the whole matrix.
#[test]
fn derived_tables_decode_without_error() {
    for entry in corpus() {
        let file = parse(&entry);
        let img = file.image();
        let name = &entry.file;

        img.symbols()
            .unwrap_or_else(|e| panic!("{name}: symbols: {e:?}"));
        img.dynamic_symbols()
            .unwrap_or_else(|e| panic!("{name}: dynamic_symbols: {e:?}"));
        img.dynamic()
            .unwrap_or_else(|e| panic!("{name}: dynamic: {e:?}"));
        img.relocations()
            .unwrap_or_else(|e| panic!("{name}: relocations: {e:?}"));
        img.notes()
            .unwrap_or_else(|e| panic!("{name}: notes: {e:?}"));
        img.build_id()
            .unwrap_or_else(|e| panic!("{name}: build_id: {e:?}"));
    }
}

/// The serializer's semantic contract: `try_build` recomputes the on-disk
/// layout (so it is not byte-identical), but a rebuild followed by a re-parse
/// preserves the object's identity, its loadable geometry, and its section
/// names.
#[test]
fn rebuild_preserves_semantics() {
    fn segments(img: &elfex::ElfImage) -> Vec<(u32, u64, u64)> {
        img.segments()
            .iter()
            .map(|s| (s.header.r#type.0, s.header.vaddr, s.header.memsz))
            .collect()
    }
    fn section_names(img: &elfex::ElfImage) -> Vec<String> {
        let mut names: Vec<String> = img.sections().iter().map(|s| s.name.clone()).collect();
        names.sort();
        names
    }

    for entry in corpus() {
        let file = parse(&entry);
        let before = file.image();
        let name = &entry.file;

        let rebuilt = before
            .try_build()
            .unwrap_or_else(|e| panic!("{name}: try_build: {e:?}"));
        let reparsed = ElfFile::parse(&rebuilt)
            .unwrap_or_else(|e| panic!("{name}: re-parse of rebuilt image: {e:?}"));
        let after = reparsed.image();

        assert_eq!(
            after.is_64bit(),
            before.is_64bit(),
            "{name}: class after rebuild"
        );
        assert_eq!(
            after.ident().data,
            before.ident().data,
            "{name}: byte order after rebuild"
        );
        assert_eq!(
            after.machine(),
            before.machine(),
            "{name}: machine after rebuild"
        );
        assert_eq!(
            after.header().r#type,
            before.header().r#type,
            "{name}: type after rebuild"
        );
        assert_eq!(
            after.entry_point(),
            before.entry_point(),
            "{name}: entry after rebuild"
        );
        assert_eq!(
            segments(after),
            segments(before),
            "{name}: segments after rebuild"
        );
        assert_eq!(
            section_names(after),
            section_names(before),
            "{name}: section names after rebuild"
        );
    }
}
