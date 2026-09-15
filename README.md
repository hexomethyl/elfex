# Elfex

Elfex is a `no_std`-friendly parser, editor, and builder for ELF executable
images. It deliberately distinguishes byte-for-byte files from images already
mapped by a loader, because their virtual-address-to-source translations are
different.

[![CI](https://github.com/hexomethyl/elfex/actions/workflows/ci.yml/badge.svg)](https://github.com/hexomethyl/elfex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What it supports

- Raw ELF files, loader-mapped images, and mapped images relocated to a runtime
  base.
- ELF32 and ELF64 headers, checked image-relative offset conversion, segment
  layout, zero-filled virtual tails, and trailing bytes.
- Program headers (segments), section headers, string tables, symbol tables
  (`.symtab` and `.dynsym`), and the dynamic table.
- REL and RELA relocations with per-architecture kind and width classification
  for x86 and x86-64.
- GNU notes (build-id), TLS metadata, and the `.gnu_debuglink` section.
- Lossless raw-file round trips through `ElfFile`, including trailing bytes
  beyond the last structure when the layout is unchanged.
- Strict malformed-input checks, fallible builders, structural validation, and
  positional I/O via the `ReadAt` trait.
- `no_std + alloc` support. No third-party dependencies.

Elfex targets ELF executable images such as executables (`ET_EXEC`), shared
objects (`ET_DYN`), and core dumps (`ET_CORE`). Relocatable object files
(`ET_REL`) are parsed but receive no special link-time support. DWARF debug
info parsing is intentionally out of scope; pass section bytes to a DWARF
crate such as `gimli`.

## Installation

```toml
[dependencies]
elfex = "0.1"
```

For `no_std + alloc`:

```toml
[dependencies]
elfex = { version = "0.1", default-features = false }
```

Elfex 0.1 requires Rust 1.88 or newer.

The default `std` feature adds filesystem helpers, `FileReader`, and standard
I/O error conversion. Parsing, building, mapped-image handling, validation, and
in-memory readers remain available without it.

## Core types

| Type | Use it for |
| --- | --- |
| `ElfFile` | A complete raw file whose trailing bytes must be preserved |
| `ElfImage` | A normalized executable image parsed from raw or loader-mapped bytes |
| `ElfHeaders` | Header-only inspection without loading segment payloads |
| `ElfBuilder` | Constructing a new executable image |

## Quick start

```rust,no_run
use elfex::ElfFile;

let bytes = std::fs::read("example")?;
let file = ElfFile::parse(&bytes)?;
let image = file.image();

println!("64-bit: {}", image.is_64bit());
println!("entry point: {:#x}", image.entry_point());
println!("image base: {:#x}", image.image_base());

if let Ok(Some(dynamic)) = image.dynamic() {
    for lib in dynamic.needed(&image) {
        println!("needs {lib}");
    }
}
# Ok::<(), elfex::Error>(())
```

Use `ElfImage::parse(raw_bytes)` when trailing bytes do not need to survive
rebuilding, or `ElfFile::parse(raw_bytes)` when they do.

## Raw files versus mapped images

```rust,no_run
use elfex::ElfImage;

# let raw_file_bytes: &[u8] = &[];
# let mapped_image: &[u8] = &[];
// Raw file: segment payloads are addressed by p_offset.
let raw = ElfImage::parse(raw_file_bytes)?;

// Loader-mapped image: segment payloads are addressed by p_vaddr.
let mapped = ElfImage::parse_mapped(mapped_image)?;

// Preserve the actual load base for address-bearing structures such as GOT.
let relocated = ElfImage::parse_mapped_at(mapped_image, 0x7f00_0000_0000)?;

assert_eq!(raw.runtime_image_base(), raw.image_base());
assert_eq!(relocated.runtime_image_base(), 0x7f00_0000_0000);
# Ok::<(), elfex::Error>(())
```

`ElfImage::to_mapped_image()` creates loader-style bytes at the preferred image
base. `to_mapped_image_at(base)` also applies supported relative relocations
for a different runtime base.

For a remote process or another random-access source, implement `ReadAt` and
use:

```text
ElfImage::read_from(&reader, source_offset)
ElfImage::read_mapped_from(&reader, source_offset, runtime_image_base)
```

## Image-relative offsets

ELF has no RVA. Elfex defines an **image-relative offset**
`ioff = vaddr - image_base` as the uniform addressing model:

```rust,no_run
use elfex::ElfImage;

# let bytes: &[u8] = &[];
let image = ElfImage::parse(bytes)?;

// Convert an ioff to a file offset.
let file_offset = image.ioff_to_offset(0x1000);

// Read bytes at an image-relative offset.
let code = image.read_at_ioff(0x1000, 16);
# Ok::<(), elfex::Error>(())
```

## Building an image

```rust,no_run
use elfex::{ElfBuilder, ElfType, Machine, SegmentFlags};

let image = ElfBuilder::new()
    .machine(Machine::X86_64)
    .elf_type(ElfType::Exec)
    .entry(0x40_1000)
    .add_load(
        0x40_1000,
        SegmentFlags(SegmentFlags::READ | SegmentFlags::EXECUTE),
        vec![0xf4; 256],
    )
    .build();

let raw_file = image.try_build()?;
assert!(!raw_file.is_empty());
# Ok::<(), elfex::Error>(())
```

Builders are fallible. Prefer `try_build()` when input or edits are not fully
trusted.

## Module layout

| Module | Contents |
| --- | --- |
| `elf` | `ElfImage` container with parse, inspect, build, edit, and validate submodules |
| `elf_file` | `ElfFile` lossless wrapper preserving trailing bytes |
| `header` | ELF and program/section header types, `ElfHeaders` for header-only inspection |
| `program` | Program headers, `Segment`, `SegmentType`, `SegmentFlags` |
| `section` | Section headers, `Section`, `SectionType`, `SectionFlags` |
| `symbol` | `Symbol`, `SymbolTable`, bind/type/visibility enums |
| `reloc` | `RelocationEntry`, `RelocationSection`, architecture-aware kind/width |
| `dynamic` | `DynamicTable`, `DynamicEntry`, `DynTag` constants |
| `notes` | GNU note parsing (build-id, ABI tag) |
| `tls` | `TlsInfo` extracted from `PT_TLS` |
| `validation` | Structural validation result types |
| `reader` | Positional `ReadAt` trait and in-memory/file readers |
| `builder` | `ElfBuilder` fluent construction API |

Nested implementation modules use Rust's modern `module.rs` plus
`module/child.rs` layout; the older `module/mod.rs` form is intentionally not
used.

## Development

```bash
# Full check matrix
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features
cargo doc --no-deps --all-features
cargo doc --no-deps --no-default-features
```

Warnings are denied by the package manifest, so the policy also applies to
direct Cargo commands.

## License

Licensed under the [MIT License](LICENSE).
