# ELF feature corpus provenance

This directory holds a corpus built from the toy sources in `src/`. Where
`tests/corpus/` targets *breadth* (many architectures, classes, and byte
orders), this corpus targets *feature depth* on the two x86 ABIs: the ELF
constructs a real toolchain emits, and that `elfex` must decode correctly for
its consumers.

Unlike `tests/corpus/`, every input here is compiled from sources in this
repository, so the fixtures are unambiguously redistributable under this
crate's MIT license.

## Coverage

| Dimension | Values present |
| --------- | -------------- |
| Class | ELF32 (i386), ELF64 (x86-64) |
| Type | `ET_EXEC` (non-PIE, copy-reloc), `ET_DYN` (PIE exe, shared object, static-PIE), `ET_REL` (unlinked objects) |
| Relocation form | `RELA` with explicit addends (x86-64), `REL` with implicit addends (i386) |
| Relocation kinds | `RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `COPY`, `IRELATIVE`, `TPOFF64`, `DTPMOD64`, `DTPOFF64`, `TLSGD`, `GOTTPOFF`, `PC32`, `PLT32`, `64`, `REX_GOTPCRELX`, and the `R_386_*` equivalents |
| TLS | `PT_TLS`, `.tdata`, `.tbss`, local-exec, initial-exec, and general-dynamic models |
| Dynamic tags | `NEEDED`, `SONAME`, `RPATH`, `RUNPATH`, `HASH`, `GNU_HASH`, `FLAGS`, `FLAGS_1`, `INIT_ARRAY`, `FINI_ARRAY`, `VERDEF`, `VERNEED` |
| Symbol versioning | `.gnu.version`, `.gnu.version_d`, `.gnu.version_r` |
| Visibility | `STV_DEFAULT`, `STV_HIDDEN`, `STV_PROTECTED` |
| Binding | `STB_LOCAL`, `STB_GLOBAL`, `STB_WEAK` |
| Symbol types | `STT_FUNC`, `STT_OBJECT`, `STT_TLS`, `STT_GNU_IFUNC`, `STT_FILE`, `STT_SECTION` |
| Sections | COMDAT `SHT_GROUP`, `SHF_COMPRESSED` debug sections, `.gnu_debuglink`, `.eh_frame`, `.gcc_except_table`, `.debug_*` |
| Linking | dynamic, static, static-PIE, stripped, separate debug link |
| Producers | gcc 15, g++ 15, clang 21, GNU ld 2.44 |

## Regenerating

```sh
./build.sh                                        # compiles bin/ from src/
python3 generate_features_manifest.py > features.manifest
```

`build.sh` records the exact command line behind every fixture. The tests never
invoke a compiler: they read the committed binaries, so CI needs no toolchain,
no multilib, and no network. Regeneration is only needed when the corpus itself
changes.

Builds are kept reproducible where it is cheap to do so: build IDs are
content-derived (`--build-id=sha1`), `SOURCE_DATE_EPOCH` is pinned, and
`-ffile-prefix-map` normalizes the paths embedded in debug info so output does
not depend on the checkout location. Exact bytes still depend on the installed
compiler and linker versions, which is why the oracle is regenerated alongside
the binaries rather than asserted as fixed constants.

## The oracle: `features.manifest`

`features.manifest` is the expected-values oracle the tests assert `elfex`
against. It is produced by `generate_features_manifest.py`, an **independent**
raw-ELF decoder that shares no code with `elfex`. Per file it records: ELF
class, byte order, OS ABI, `e_type`, `e_machine`, entry point, table counts,
derived image base and span, the full section and program header tables, the
dynamic array, `DT_NEEDED`/`DT_SONAME`/`DT_RPATH`/`DT_RUNPATH` strings, the TLS
header, notes and build ID, every relocation table with its `REL`/`RELA` form
and entry count, an aggregate relocation-type histogram, the first entry of each
relocation table, symbol-table sizes, per-table binding/type/visibility
histograms, and the full decode of a pinned set of named symbols.

Two derived values are reproduced independently rather than read from the file,
matching `elfex`'s documented definitions:

- `imagebase` — `min(PT_LOAD.p_vaddr)` over segments with `p_memsz != 0`,
  rounded down to `page`, where `page` is the largest `p_align > 1` among those
  segments, floored at `0x1000`.
- `imagespan` — `max(p_vaddr + p_memsz)` rounded up to `page`, minus the base.

Notes are decoded from `PT_NOTE` *segments* only, matching `ElfImage::notes`, so
unlinked `ET_REL` objects correctly report none even though they carry
`SHT_NOTE` sections.

The generator was cross-checked against GNU `readelf` (binutils 2.44) on 64-bit,
32-bit, and `ET_REL` representatives: ELF class, machine, type, entry point,
header counts, relocation-type histograms, and the signed-addend decode of
`RELA` tables all agree. `readelf` is the canonical field oracle and is used at
*generation* time only, so the tests stay hermetic and offline.

The `sha256` line in each block pins the fixture's digest, so corpus drift is
detectable with a standard `sha256sum` check and the tests fail loudly if a
binary is regenerated without refreshing the oracle.

## Pinned symbols

The manifest records the full decode of named symbols from the toy sources
rather than every symbol in each file. Static binaries carry thousands of libc
symbols whose addresses are toolchain-dependent and are not what these tests
assert. The per-table binding/type/visibility histograms still cover the whole
symbol table, so a decode error in an unpinned symbol is caught by the
distribution even when its exact value is not pinned.
