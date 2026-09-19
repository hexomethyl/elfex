//! Feature-depth ELF tests over a locally compiled corpus.
//!
//! Where `tests/corpus.rs` drives `elfex` across many architectures, these
//! tests drive it across the ELF *features* a real toolchain emits: dynamic
//! linking, both relocation forms, thread-local storage, indirect functions,
//! static initialization, symbol versioning and visibility, COMDAT groups, and
//! unlinked objects. Every fixture is compiled from `tests/features/src/`; see
//! `tests/features/PROVENANCE.md` for the build matrix and the oracle.

#[path = "features/harness.rs"]
mod harness;

use elfex::reloc::{relocation_kind, relocation_width};
use elfex::validation::ValidationCode;
use elfex::{
    DynTag, ElfClass, ElfFile, ElfImage, Endian, Machine, RelocKind, SectionType, StringTable,
    SymbolBind, SymbolType, SymbolVisibility,
};
use harness::{Entry, corpus, fixture};

const ET_REL: u16 = 1;
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;

fn image_of(entry: &Entry) -> ElfImage {
    let bytes = entry.read_bytes();
    ElfFile::parse(&bytes)
        .unwrap_or_else(|error| panic!("{}: parse failed: {error:?}", entry.file))
        .into_image()
}

fn image_named(name: &str) -> ElfImage {
    image_of(&fixture(name))
}

/// The corpus is committed, so a missing or regenerated fixture must fail
/// loudly rather than silently reduce coverage.
#[test]
fn every_oracle_entry_has_a_fixture_with_the_pinned_digest() {
    let entries = corpus();
    assert!(
        entries.len() >= 30,
        "expected the full feature corpus; found {} entries",
        entries.len()
    );
    for entry in entries {
        let bytes = entry.read_bytes();
        let digest = sha256_hex(&bytes);
        assert_eq!(
            digest, entry.sha256,
            "{}: fixture digest drifted from the oracle; regenerate features.manifest",
            entry.file
        );
    }
}

#[test]
fn identification_and_header_fields_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let ident = image.ident();

        let expected_class = if entry.class_bits == 64 {
            ElfClass::Elf64
        } else {
            ElfClass::Elf32
        };
        assert_eq!(ident.class, expected_class, "{name}: class");
        let expected_endian = if entry.little_endian {
            Endian::Little
        } else {
            Endian::Big
        };
        assert_eq!(ident.data, expected_endian, "{name}: byte order");
        assert_eq!(ident.os_abi.value(), entry.osabi, "{name}: OS ABI");
        assert_eq!(
            image.header().r#type.to_u16(),
            entry.etype,
            "{name}: object type"
        );
        assert_eq!(image.machine(), Machine(entry.machine), "{name}: machine");
        assert_eq!(image.entry_point(), entry.entry, "{name}: entry point");
        assert_eq!(
            usize::from(image.header().phnum),
            entry.phnum,
            "{name}: program header count"
        );
        assert_eq!(
            usize::from(image.header().shnum),
            entry.shnum,
            "{name}: section header count"
        );
    }
}

/// `image_base` and `image_span` are derived, not stored. The oracle
/// recomputes them independently, so this pins the geometry across PIE,
/// non-PIE, static-PIE, shared objects, and unlinked objects (which have no
/// loadable segments at all).
#[test]
fn derived_image_geometry_matches_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        assert_eq!(
            image.image_base(),
            entry.image_base,
            "{}: image base",
            entry.file
        );
        assert_eq!(
            image.image_span(),
            entry.image_span,
            "{}: image span",
            entry.file
        );
    }
}

#[test]
fn program_header_tables_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        assert_eq!(
            image.segments().len(),
            entry.segments.len(),
            "{name}: segment count"
        );
        for (index, (segment, expected)) in
            image.segments().iter().zip(&entry.segments).enumerate()
        {
            let header = &segment.header;
            assert_eq!(header.r#type.0, expected.kind, "{name}: seg {index} type");
            assert_eq!(header.vaddr, expected.vaddr, "{name}: seg {index} vaddr");
            assert_eq!(header.filesz, expected.filesz, "{name}: seg {index} filesz");
            assert_eq!(header.memsz, expected.memsz, "{name}: seg {index} memsz");
            assert_eq!(
                header.flags.value(),
                expected.flags,
                "{name}: seg {index} flags"
            );
            assert_eq!(header.align, expected.align, "{name}: seg {index} align");
        }
    }
}

#[test]
fn section_header_tables_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        assert_eq!(
            image.sections().len(),
            entry.sections.len(),
            "{name}: section count"
        );
        for (index, (section, expected)) in
            image.sections().iter().zip(&entry.sections).enumerate()
        {
            let header = &section.header;
            assert_eq!(section.name, expected.name, "{name}: sec {index} name");
            assert_eq!(header.r#type.0, expected.kind, "{name}: sec {index} type");
            assert_eq!(header.addr, expected.addr, "{name}: sec {index} addr");
            assert_eq!(header.size, expected.size, "{name}: sec {index} size");
            assert_eq!(
                header.flags.value(),
                expected.flags,
                "{name}: sec {index} flags"
            );
            assert_eq!(
                header.entsize, expected.entsize,
                "{name}: sec {index} entsize"
            );
        }
    }
}

#[test]
fn dynamic_arrays_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let decoded = image
            .dynamic()
            .unwrap_or_else(|error| panic!("{name}: dynamic: {error:?}"));
        let actual: Vec<(u64, u64)> = decoded
            .map(|table| {
                table
                    .entries()
                    .iter()
                    .map(|record| (record.tag.value(), record.value))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(actual, entry.dynamic, "{name}: dynamic array");
    }
}

#[test]
fn needed_soname_and_search_paths_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let needed = image
            .needed_libraries()
            .unwrap_or_else(|error| panic!("{name}: needed: {error:?}"));
        assert_eq!(needed, entry.needed, "{name}: DT_NEEDED list");

        let Some(table) = image
            .dynamic()
            .unwrap_or_else(|error| panic!("{name}: dynamic: {error:?}"))
        else {
            assert!(entry.soname.is_none(), "{name}: soname without a dynamic table");
            continue;
        };
        let dynstr = image
            .sections()
            .iter()
            .find(|section| section.name == ".dynstr")
            .map(|section| section.data.as_slice())
            .unwrap_or_default();
        let strtab = StringTable::new(dynstr);
        assert_eq!(table.soname(strtab), entry.soname, "{name}: DT_SONAME");
        assert_eq!(table.runpath(strtab), entry.runpath, "{name}: DT_RUNPATH");
        assert_eq!(table.rpath(strtab), entry.rpath, "{name}: DT_RPATH");
    }
}

/// The decisive relocation test: every table's form and entry count, plus a
/// full field decode of each table's first entry. This covers `RELA` with
/// explicit signed addends (x86-64) and `REL` with implicit addends (i386),
/// and therefore both `r_info` split conventions.
#[test]
fn relocation_tables_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let tables = image
            .relocations()
            .unwrap_or_else(|error| panic!("{name}: relocations: {error:?}"));
        assert_eq!(
            tables.len(),
            entry.rel_tables.len(),
            "{name}: relocation table count"
        );

        let mut first_entries = Vec::new();
        for (index, (table, expected)) in tables.iter().zip(&entry.rel_tables).enumerate() {
            assert_eq!(
                table.is_rela(),
                expected.is_rela,
                "{name}: table {index} ({}) REL/RELA form",
                expected.name
            );
            assert_eq!(
                table.entries().len(),
                expected.count,
                "{name}: table {index} ({}) entry count",
                expected.name
            );
            if let Some(record) = table.entries().first() {
                first_entries.push((expected.name.clone(), *record));
            }
        }

        assert_eq!(
            first_entries.len(),
            entry.rel_first.len(),
            "{name}: tables with a first entry"
        );
        for ((table_name, record), expected) in first_entries.iter().zip(&entry.rel_first) {
            let label = format!("{name}: first entry of {table_name}");
            assert_eq!(*table_name, expected.name, "{label}: table identity");
            assert_eq!(record.offset, expected.offset, "{label}: offset");
            assert_eq!(record.symbol, expected.symbol, "{label}: symbol index");
            assert_eq!(record.r_type, expected.r_type, "{label}: type");
            assert_eq!(record.addend, expected.addend, "{label}: addend");
        }
    }
}

#[test]
fn relocation_type_histograms_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let tables = image
            .relocations()
            .unwrap_or_else(|error| panic!("{name}: relocations: {error:?}"));

        let mut counts: Vec<(u32, usize)> = Vec::new();
        for table in &tables {
            for record in table.entries() {
                match counts.iter_mut().find(|(key, _)| *key == record.r_type) {
                    Some((_, count)) => *count += 1,
                    None => counts.push((record.r_type, 1)),
                }
            }
        }
        counts.sort_unstable();
        assert_eq!(counts, entry.rel_types, "{name}: relocation type histogram");
    }
}

#[test]
fn symbol_tables_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;

        for (label, table) in [
            (
                "symtab",
                image
                    .symbols()
                    .unwrap_or_else(|error| panic!("{name}: symbols: {error:?}")),
            ),
            (
                "dynsym",
                image
                    .dynamic_symbols()
                    .unwrap_or_else(|error| panic!("{name}: dynamic_symbols: {error:?}")),
            ),
        ] {
            let expected_count = if label == "symtab" {
                entry.symtab_count
            } else {
                entry.dynsym_count
            };
            assert_eq!(
                table.symbols().len(),
                expected_count,
                "{name}: {label} entry count"
            );

            assert_histogram(
                name,
                label,
                "binding",
                &entry.sym_binds,
                table.symbols().iter().map(|symbol| symbol.bind.to_u8()),
            );
            assert_histogram(
                name,
                label,
                "type",
                &entry.sym_types,
                table.symbols().iter().map(|symbol| symbol.sym_type.to_u8()),
            );
            assert_histogram(
                name,
                label,
                "visibility",
                &entry.sym_visibilities,
                table
                    .symbols()
                    .iter()
                    .map(|symbol| symbol.visibility.to_u8()),
            );

            for expected in entry.symbols.iter().filter(|symbol| symbol.table == label) {
                let found = table
                    .symbols()
                    .iter()
                    .find(|symbol| symbol.name == expected.name)
                    .unwrap_or_else(|| {
                        panic!("{name}: {label} is missing pinned symbol {:?}", expected.name)
                    });
                let label = format!("{name}: {label} symbol {:?}", expected.name);
                assert_eq!(found.value, expected.value, "{label}: value");
                assert_eq!(found.size, expected.size, "{label}: size");
                assert_eq!(found.bind.to_u8(), expected.bind, "{label}: binding");
                assert_eq!(found.sym_type.to_u8(), expected.sym_type, "{label}: type");
                assert_eq!(
                    found.visibility.to_u8(),
                    expected.visibility,
                    "{label}: visibility"
                );
                assert_eq!(found.shndx, expected.shndx, "{label}: section index");
            }
        }
    }
}

fn assert_histogram(
    file: &str,
    table: &str,
    axis: &str,
    expected: &[(String, u8, usize)],
    actual: impl Iterator<Item = u8>,
) {
    let mut counts: Vec<(u8, usize)> = Vec::new();
    for key in actual {
        match counts.iter_mut().find(|(candidate, _)| *candidate == key) {
            Some((_, count)) => *count += 1,
            None => counts.push((key, 1)),
        }
    }
    counts.sort_unstable();
    let wanted: Vec<(u8, usize)> = expected
        .iter()
        .filter(|(name, _, _)| name == table)
        .map(|(_, key, count)| (*key, *count))
        .collect();
    assert_eq!(counts, wanted, "{file}: {table} {axis} histogram");
}

#[test]
fn notes_and_build_ids_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let notes = image
            .notes()
            .unwrap_or_else(|error| panic!("{name}: notes: {error:?}"));
        assert_eq!(notes.len(), entry.notes.len(), "{name}: note count");
        for (index, (note, expected)) in notes.iter().zip(&entry.notes).enumerate() {
            assert_eq!(note.name(), expected.name, "{name}: note {index} owner");
            assert_eq!(
                note.note_type(),
                expected.note_type,
                "{name}: note {index} type"
            );
            assert_eq!(
                note.descriptor().len(),
                expected.descsz,
                "{name}: note {index} descriptor size"
            );
        }

        let build_id = image
            .build_id()
            .unwrap_or_else(|error| panic!("{name}: build_id: {error:?}"))
            .map(|bytes| {
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            });
        assert_eq!(build_id, entry.build_id, "{name}: GNU build id");
    }
}

#[test]
fn tls_headers_match_the_oracle() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let actual = image
            .tls()
            .map(|tls| (tls.template_vaddr(), tls.file_size(), tls.mem_size(), tls.align()));
        assert_eq!(actual, entry.tls, "{name}: PT_TLS header");
        if let Some(tls) = image.tls() {
            assert_eq!(
                tls.zero_fill_size(),
                tls.mem_size() - tls.file_size(),
                "{name}: TLS zero-fill size"
            );
        }
    }
}

/// Real toolchain output must pass structural validation. Unlinked objects are
/// the documented exception: they carry no loadable segment.
#[test]
fn structural_validation_accepts_linked_output_and_flags_unlinked_objects() {
    for entry in corpus() {
        let image = image_of(&entry);
        let name = &entry.file;
        let result = image.validate();

        if entry.etype == ET_REL {
            let codes: Vec<ValidationCode> =
                result.issues.iter().map(|issue| issue.code).collect();
            assert!(
                codes.contains(&ValidationCode::NoLoadSegments),
                "{name}: an unlinked object should report NoLoadSegments; got {codes:?}"
            );
        } else {
            assert!(
                result.is_ok(),
                "{name}: linked output should validate cleanly; got {:?}",
                result.issues
            );
        }
    }
}

#[test]
fn rebuilding_every_fixture_preserves_its_semantics() {
    for entry in corpus() {
        let before = image_of(&entry);
        let name = &entry.file;
        let rebuilt = before
            .try_build()
            .unwrap_or_else(|error| panic!("{name}: try_build: {error:?}"));
        let after = ElfFile::parse(&rebuilt)
            .unwrap_or_else(|error| panic!("{name}: re-parse: {error:?}"))
            .into_image();

        assert_eq!(after.ident(), before.ident(), "{name}: ident after rebuild");
        assert_eq!(
            after.machine(),
            before.machine(),
            "{name}: machine after rebuild"
        );
        assert_eq!(
            after.entry_point(),
            before.entry_point(),
            "{name}: entry after rebuild"
        );
        assert_eq!(
            after.image_base(),
            before.image_base(),
            "{name}: image base after rebuild"
        );

        let names = |image: &ElfImage| {
            let mut out: Vec<String> = image
                .sections()
                .iter()
                .map(|section| section.name.clone())
                .collect();
            out.sort();
            out
        };
        assert_eq!(
            names(&after),
            names(&before),
            "{name}: section names after rebuild"
        );

        let relocation_counts = |image: &ElfImage| -> Vec<(bool, usize)> {
            image
                .relocations()
                .expect("relocations decode")
                .iter()
                .map(|table| (table.is_rela(), table.entries().len()))
                .collect()
        };
        assert_eq!(
            relocation_counts(&after),
            relocation_counts(&before),
            "{name}: relocation tables after rebuild"
        );
    }
}

// ---------------------------------------------------------------------------
// Targeted feature assertions
// ---------------------------------------------------------------------------

/// Both `r_info` split conventions decode correctly: x86-64 packs the symbol
/// index in the high 32 bits and carries an explicit signed addend, while i386
/// packs it above an 8-bit type field and has no addend.
#[test]
fn rel_and_rela_forms_decode_their_distinct_layouts() {
    let rela = image_named("reloc_x64.o");
    let text = rela
        .relocations()
        .expect("x86-64 relocations decode")
        .into_iter()
        .next()
        .expect("an object has at least one relocation table");
    assert!(text.is_rela(), "an x86-64 object uses the RELA form");
    assert!(
        text.entries().iter().all(|record| record.addend.is_some()),
        "every RELA entry carries an explicit addend"
    );
    assert!(
        text.entries().iter().any(|record| record.addend == Some(-4)),
        "a PC-relative call site has a negative addend"
    );
    assert!(
        text.entries().iter().all(|record| record.r_type < 64),
        "a 64-bit split must not leak the symbol index into the type"
    );

    let rel = image_named("reloc_x86.o");
    let rel_text = rel
        .relocations()
        .expect("i386 relocations decode")
        .into_iter()
        .next()
        .expect("an object has at least one relocation table");
    assert!(!rel_text.is_rela(), "an i386 object uses the REL form");
    assert!(
        rel_text.entries().iter().all(|record| record.addend.is_none()),
        "no REL entry carries an explicit addend"
    );
    assert!(
        rel_text.entries().iter().all(|record| record.r_type <= 0xff),
        "an i386 type field is eight bits wide"
    );
    assert!(
        rel_text.entries().iter().any(|record| record.symbol > 0),
        "an i386 symbol index decodes from above the type field"
    );
}

/// Every relocation kind the corpus actually contains classifies as intended,
/// across both x86 ABIs.
#[test]
fn relocation_kinds_classify_across_both_x86_abis() {
    let x86_64 = Machine(EM_X86_64);
    let i386 = Machine(EM_386);

    // Kinds observed in the corpus, keyed by the fixture that supplies them.
    for (name, r_type, kind, width) in [
        ("dyn_pie", 8u32, RelocKind::Relative, Some(8u8)),
        ("dyn_pie", 6, RelocKind::GlobalData, Some(8)),
        ("dyn_pie", 7, RelocKind::JumpSlot, Some(8)),
        ("copy_reloc", 5, RelocKind::Copy, Some(8)),
        ("libfeature.so", 16, RelocKind::Tls, Some(8)),
        ("libfeature.so", 17, RelocKind::Tls, Some(8)),
        ("libtls_ie.so", 18, RelocKind::Tls, Some(8)),
        ("cpp_comdat.o", 2, RelocKind::Other, Some(4)),
    ] {
        assert_eq!(
            relocation_kind(x86_64, r_type),
            kind,
            "x86-64 type {r_type} (from {name}) classification"
        );
        assert_eq!(
            relocation_width(x86_64, r_type),
            width,
            "x86-64 type {r_type} (from {name}) width"
        );
        let present = fixture(name).rel_type_count(r_type);
        assert!(present > 0, "{name} should contain a type {r_type} relocation");
    }

    for (name, r_type, kind) in [
        ("dyn_x86", 8u32, RelocKind::Relative),
        ("dyn_x86", 6, RelocKind::GlobalData),
        ("dyn_x86", 7, RelocKind::JumpSlot),
        ("reloc_x86.o", 1, RelocKind::Absolute),
        ("libtls_ie_x86.so", 14, RelocKind::Tls),
    ] {
        assert_eq!(
            relocation_kind(i386, r_type),
            kind,
            "i386 type {r_type} (from {name}) classification"
        );
        let present = fixture(name).rel_type_count(r_type);
        assert!(present > 0, "{name} should contain a type {r_type} relocation");
    }

    // i386 copy relocations classify even though no fixture links one.
    assert_eq!(relocation_kind(i386, 5), RelocKind::Copy);
    assert_eq!(relocation_width(i386, 5), Some(4));
    // An unknown machine falls back rather than guessing a width.
    assert_eq!(relocation_kind(Machine(0), 8), RelocKind::Other);
    assert_eq!(relocation_width(Machine(0), 8), None);
}

#[test]
fn thread_local_storage_is_exposed_for_every_model() {
    let exe = image_named("tls_exe");
    let tls = exe.tls().expect("tls_exe declares PT_TLS");
    assert!(tls.mem_size() > tls.file_size(), ".tbss adds zero-fill bytes");
    assert!(tls.file_size() > 0, ".tdata contributes initialized bytes");
    assert!(tls.align() >= 8, "a double array raises the TLS alignment");
    assert!(
        exe.sections().iter().any(|section| section.name == ".tdata"),
        "tls_exe has a .tdata section"
    );
    assert!(
        exe.sections()
            .iter()
            .any(|section| section.name == ".tbss"
                && section.header.r#type.0 == SectionType::NOBITS.0),
        "tls_exe has a NOBITS .tbss section"
    );

    // Thread-local symbols decode as STT_TLS.
    let exe_symbols = exe.symbols().expect("symbols decode");
    let tls_symbols: Vec<&str> = exe_symbols
        .symbols()
        .iter()
        .filter(|symbol| symbol.sym_type == SymbolType::Tls)
        .map(|symbol| symbol.name.as_str())
        .collect();
    for wanted in ["tls_initialized", "tls_zero", "tls_aligned"] {
        assert!(
            tls_symbols.contains(&wanted),
            "{wanted} should decode as a TLS symbol; got {tls_symbols:?}"
        );
    }

    // A shared object keeps the general-dynamic pair; initial-exec keeps TPOFF.
    let shared = fixture("libfeature.so");
    assert!(shared.rel_type_count(16) > 0, "DTPMOD64 in a shared object");
    assert!(shared.rel_type_count(17) > 0, "DTPOFF64 in a shared object");
    assert!(
        fixture("libtls_ie.so").rel_type_count(18) > 0,
        "TPOFF64 for initial-exec TLS"
    );
}

#[test]
fn indirect_functions_decode_as_gnu_ifunc() {
    let image = image_named("ifunc_dyn");
    let symbols = image.symbols().expect("symbols decode");
    let ifuncs: Vec<&str> = symbols
        .symbols()
        .iter()
        .filter(|symbol| symbol.sym_type == SymbolType::GnuIfunc)
        .map(|symbol| symbol.name.as_str())
        .collect();
    assert!(
        ifuncs.contains(&"picked"),
        "the ifunc symbol should decode as STT_GNU_IFUNC; got {ifuncs:?}"
    );

    // R_X86_64_IRELATIVE is present and is deliberately not treated as a
    // plain relative relocation: its target is produced by a resolver call.
    assert!(
        fixture("ifunc_dyn").rel_type_count(37) > 0,
        "an ifunc binary carries IRELATIVE relocations"
    );
    assert_ne!(
        relocation_kind(Machine(EM_X86_64), 37),
        RelocKind::Relative,
        "IRELATIVE must not be rebased as a stored pointer"
    );
    assert!(
        fixture("static_pie").rel_type_count(37) >= 20,
        "a static-PIE binary resolves many ifuncs"
    );
}

#[test]
fn symbol_visibility_and_binding_decode_from_real_output() {
    let image = image_named("dyn_pie");
    let symbols = image.symbols().expect("symbols decode");
    let find = |name: &str| {
        symbols
            .symbols()
            .iter()
            .find(|symbol| symbol.name == name)
            .unwrap_or_else(|| panic!("dyn_pie should define {name}"))
    };

    assert_eq!(find("visible_default").visibility, SymbolVisibility::Default);
    assert_eq!(find("visible_hidden").visibility, SymbolVisibility::Hidden);
    assert_eq!(
        find("visible_protected").visibility,
        SymbolVisibility::Protected
    );

    assert_eq!(find("weak_function").bind, SymbolBind::Weak);
    assert_eq!(find("weak_function").sym_type, SymbolType::Func);
    assert_eq!(find("weak_data").bind, SymbolBind::Weak);
    assert_eq!(find("weak_data").sym_type, SymbolType::Object);
    assert_eq!(find("visible_default").bind, SymbolBind::Global);

    // Hidden symbols are localized out of the dynamic table.
    let dynamic_table = image
        .dynamic_symbols()
        .expect("dynamic symbols decode");
    let dynamic_names: Vec<&str> = dynamic_table
        .symbols()
        .iter()
        .map(|symbol| symbol.name.as_str())
        .collect();
    assert!(
        !dynamic_names.contains(&"visible_hidden"),
        "a hidden symbol must not appear in .dynsym"
    );
}

#[test]
fn versioned_shared_object_exposes_its_soname_and_version_sections() {
    let image = image_named("libfeature.so");
    let table = image
        .dynamic()
        .expect("dynamic decodes")
        .expect("a shared object has a dynamic table");
    let dynstr = image
        .sections()
        .iter()
        .find(|section| section.name == ".dynstr")
        .map(|section| section.data.as_slice())
        .unwrap_or_default();
    let strtab = StringTable::new(dynstr);

    assert_eq!(table.soname(strtab).as_deref(), Some("libfeature.so.1"));
    assert!(
        table.find(DynTag::VERDEF).is_some(),
        "DT_VERDEF is present"
    );
    for wanted in [".gnu.version", ".gnu.version_d", ".gnu.version_r"] {
        assert!(
            image.sections().iter().any(|section| section.name == wanted),
            "libfeature.so should carry {wanted}"
        );
    }

    // The version script localizes everything it does not export.
    let exported_table = image
        .dynamic_symbols()
        .expect("dynamic symbols decode");
    let exported: Vec<&str> = exported_table
        .symbols()
        .iter()
        .filter(|symbol| symbol.shndx != 0)
        .map(|symbol| symbol.name.as_str())
        .collect();
    assert!(exported.contains(&"feature_v1"), "feature_v1 is exported");
    assert!(exported.contains(&"feature_v2"), "feature_v2 is exported");
    assert!(
        !exported.contains(&"feature_internal"),
        "a hidden symbol stays out of the dynamic table"
    );
}

#[test]
fn search_paths_distinguish_runpath_from_rpath() {
    let runpath = fixture("dyn_runpath");
    assert_eq!(runpath.runpath.as_deref(), Some("/opt/elfex"));
    assert!(runpath.rpath.is_none(), "new dtags emit RUNPATH only");

    let rpath = fixture("dyn_rpath");
    assert_eq!(rpath.rpath.as_deref(), Some("/opt/elfex"));
    assert!(rpath.runpath.is_none(), "legacy dtags emit RPATH only");
}

#[test]
fn hash_styles_are_distinguishable() {
    let sysv = image_named("dyn_sysvhash");
    let sysv_dynamic = sysv.dynamic().expect("decodes").expect("has a table");
    assert!(sysv_dynamic.find(DynTag::HASH).is_some(), "DT_HASH present");
    assert!(
        sysv_dynamic.find(DynTag::GNU_HASH).is_none(),
        "sysv style omits DT_GNU_HASH"
    );

    let gnu = image_named("dyn_gnuhash");
    let gnu_dynamic = gnu.dynamic().expect("decodes").expect("has a table");
    assert!(
        gnu_dynamic.find(DynTag::GNU_HASH).is_some(),
        "DT_GNU_HASH present"
    );
    assert!(
        gnu_dynamic.find(DynTag::HASH).is_none(),
        "gnu style omits DT_HASH"
    );
}

#[test]
fn static_and_stripped_fixtures_report_empty_tables() {
    let statically_linked = image_named("static_exe");
    assert!(
        statically_linked
            .dynamic()
            .expect("dynamic decodes")
            .is_none(),
        "a static binary has no dynamic table"
    );
    assert!(
        statically_linked
            .needed_libraries()
            .expect("needed decodes")
            .is_empty(),
        "a static binary needs no shared libraries"
    );
    assert!(
        statically_linked
            .dynamic_symbols()
            .expect("dynamic symbols decode")
            .symbols()
            .is_empty(),
        "a static binary has no dynamic symbol table"
    );
    assert!(
        !statically_linked.symbols().expect("symbols decode").symbols().is_empty(),
        "a static binary still has a static symbol table"
    );

    let stripped = image_named("dyn_stripped");
    assert!(
        stripped.symbols().expect("symbols decode").symbols().is_empty(),
        "a stripped binary has no .symtab"
    );
    assert!(
        !stripped.dynamic_symbols().expect("decodes").symbols().is_empty(),
        "stripping keeps the dynamic symbol table"
    );
    assert!(
        stripped
            .build_id()
            .expect("build id decodes")
            .is_some(),
        "stripping keeps the build id note"
    );
}

#[test]
fn comdat_groups_and_compressed_debug_sections_are_visible() {
    let comdat = image_named("cpp_comdat.o");
    let groups = comdat
        .sections()
        .iter()
        .filter(|section| section.header.r#type.0 == SectionType::GROUP.0)
        .count();
    assert!(
        groups >= 5,
        "C++ template instantiation should emit COMDAT groups; found {groups}"
    );
    assert!(
        comdat
            .sections()
            .iter()
            .any(|section| section.name == ".gcc_except_table"),
        "exception handling emits .gcc_except_table"
    );

    // SHF_COMPRESSED is bit 11 (0x800).
    let compressed = image_named("dyn_debug_compressed");
    let count = compressed
        .sections()
        .iter()
        .filter(|section| section.header.flags.value() & 0x800 != 0)
        .count();
    assert!(
        count > 0,
        "compressed debug sections should carry SHF_COMPRESSED"
    );
    assert!(
        compressed
            .sections()
            .iter()
            .any(|section| section.name.starts_with(".debug_")),
        "the fixture carries DWARF sections"
    );

    assert!(
        image_named("dyn_debuglink")
            .sections()
            .iter()
            .any(|section| section.name == ".gnu_debuglink"),
        "a separated-debug build carries .gnu_debuglink"
    );
}

#[test]
fn static_initialization_arrays_are_present_and_populated() {
    for name in ["dyn_pie", "cpp_exc"] {
        let image = image_named(name);
        let init = image
            .sections()
            .iter()
            .find(|section| section.name == ".init_array")
            .unwrap_or_else(|| panic!("{name} should have an .init_array"));
        let pointer_width = u64::from(if image.ident().class == ElfClass::Elf64 {
            8u8
        } else {
            4
        });
        assert!(
            init.header.size >= pointer_width,
            "{name}: .init_array should hold at least one constructor"
        );
        assert_eq!(
            init.header.size % pointer_width,
            0,
            "{name}: .init_array is a whole number of pointers"
        );
        assert!(
            image
                .sections()
                .iter()
                .any(|section| section.name == ".fini_array"),
            "{name} should have a .fini_array"
        );
    }

    // dynamic.c registers two constructors, so the array holds two pointers.
    let image = image_named("dyn_pie");
    let init = image
        .sections()
        .iter()
        .find(|section| section.name == ".init_array")
        .expect("dyn_pie has an .init_array");
    assert!(
        init.header.size >= 16,
        "two constructors occupy two 64-bit pointers; got {}",
        init.header.size
    );
}

fn read_unsigned(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    value
}

/// Mapping an image at its preferred base must not rewrite anything: the
/// relocation-application path is reached only when the base actually moves.
#[test]
fn mapping_at_the_preferred_base_rewrites_nothing() {
    for name in ["static_pie", "dyn_pie", "dyn_x86"] {
        let image = image_named(name);
        let implicit = image
            .to_mapped_image()
            .unwrap_or_else(|error| panic!("{name}: maps at its preferred base: {error:?}"));
        let explicit = image
            .to_mapped_image_at(image.image_base())
            .unwrap_or_else(|error| panic!("{name}: maps at an explicit base: {error:?}"));
        assert_eq!(
            implicit, explicit,
            "{name}: naming the preferred base explicitly must change nothing"
        );
    }
}

/// Rebasing a mapped image adds the base delta to every pointer a relative
/// relocation names. This is the only path in `elfex` that rewrites image
/// bytes, and it is exercised here at both pointer widths: 8-byte
/// `R_X86_64_RELATIVE` and 4-byte `R_386_RELATIVE`.
#[test]
fn rebasing_a_mapped_image_shifts_every_relative_relocation() {
    for (name, width, least) in [("static_pie", 8u8, 1000usize), ("dyn_x86", 4, 10)] {
        let image = image_named(name);
        let base = image.image_base();
        let machine = image.machine();
        let delta = 0x20_0000u64;

        let at_base = image
            .to_mapped_image()
            .unwrap_or_else(|error| panic!("{name}: maps at its preferred base: {error:?}"));
        let rebased = image
            .to_mapped_image_at(base + delta)
            .unwrap_or_else(|error| panic!("{name}: maps at a shifted base: {error:?}"));
        assert_eq!(
            at_base.len(),
            rebased.len(),
            "{name}: rebasing must not resize the image"
        );

        let mut checked = 0usize;
        for table in image.relocations().expect("relocations decode") {
            for record in table.entries() {
                if relocation_kind(machine, record.r_type) != RelocKind::Relative {
                    continue;
                }
                assert_eq!(
                    relocation_width(machine, record.r_type),
                    Some(width),
                    "{name}: relative relocations are {width} bytes wide"
                );
                let ioff = record
                    .offset
                    .checked_sub(base)
                    .expect("a relative relocation sits inside the image");
                let start = usize::try_from(ioff).expect("the offset fits in memory");
                let end = start + usize::from(width);
                if end > at_base.len() {
                    continue;
                }
                let before = read_unsigned(&at_base[start..end]);
                let after = read_unsigned(&rebased[start..end]);
                let expected = if width == 8 {
                    before.wrapping_add(delta)
                } else {
                    u64::from(
                        u32::try_from(before)
                            .expect("a 4-byte slot holds a 32-bit value")
                            .wrapping_add(u32::try_from(delta).expect("the delta fits")),
                    )
                };
                assert_eq!(
                    after, expected,
                    "{name}: the pointer at image offset {ioff:#x} should shift by {delta:#x}"
                );
                checked += 1;
            }
        }
        assert!(
            checked >= least,
            "{name}: expected at least {least} relative relocations; verified {checked}"
        );
    }
}

/// Indirect-function slots are produced by a resolver call at load time, so
/// rebasing must leave them alone rather than treating them as stored
/// pointers.
#[test]
fn rebasing_leaves_indirect_function_slots_untouched() {
    let image = image_named("static_pie");
    let base = image.image_base();
    let at_base = image.to_mapped_image().expect("maps at its preferred base");
    let rebased = image
        .to_mapped_image_at(base + 0x20_0000)
        .expect("maps at a shifted base");

    let mut checked = 0usize;
    for table in image.relocations().expect("relocations decode") {
        for record in table.entries() {
            // R_X86_64_IRELATIVE
            if record.r_type != 37 {
                continue;
            }
            let ioff = record
                .offset
                .checked_sub(base)
                .expect("an ifunc slot sits inside the image");
            let start = usize::try_from(ioff).expect("the offset fits in memory");
            let end = start + 8;
            if end > at_base.len() {
                continue;
            }
            assert_eq!(
                at_base[start..end],
                rebased[start..end],
                "the ifunc slot at image offset {ioff:#x} must not be rebased"
            );
            checked += 1;
        }
    }
    assert!(checked >= 20, "static_pie should resolve many ifuncs; saw {checked}");
}

/// A minimal SHA-256 so the corpus digests can be checked without adding a
/// dependency to a `no_std`, dependency-free crate.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let mut padded = data.to_vec();
    let bit_length = u64::try_from(data.len()).expect("a fixture fits in u64") * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut base = 0;
    while base + 64 <= padded.len() {
        let chunk = &padded[base..base + 64];
        let mut w = [0u32; 64];
        for (index, slot) in w.iter_mut().take(16).enumerate() {
            let at = index * 4;
            *slot =
                u32::from_be_bytes([chunk[at], chunk[at + 1], chunk[at + 2], chunk[at + 3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
        base += 64;
    }

    state
        .iter()
        .map(|word| format!("{word:08x}"))
        .collect::<String>()
}
