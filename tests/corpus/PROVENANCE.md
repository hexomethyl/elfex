# ELF test corpus provenance

This directory holds a small, wide corpus of real-world ELF objects used by the
integration tests in `tests/corpus.rs`. The goal is breadth: many architectures,
both classes (ELF32/ELF64), both byte orders, and several object types
(`ET_EXEC`, `ET_DYN`, `ET_REL`, `ET_CORE`).

## Coverage

| Dimension | Values present |
| --------- | -------------- |
| Machine   | i386, x86-64, ARM, MIPS (32/64), PowerPC (32/64), AArch64, RISC-V 64, S/390 (32/64), SPARC V9 |
| Class     | ELF32, ELF64 |
| Byte order| little-endian, big-endian |
| Type      | `ET_EXEC`, `ET_DYN`, `ET_REL` (incl. a kernel module), `ET_CORE` |

## Sources

### `rizin/` — rizinorg/rizin-testbins
- Upstream: <https://github.com/rizinorg/rizin-testbins> (`abi_bins/elf/platforms/`),
  branch `master`.
- These binaries are curated by the Rizin project to be copyright-friendly and
  redistributable as reproducible test fixtures.
- Files: `arm-linux-androideabi-echo`, `arm-linux-gnueabi-echo`,
  `macppc-openbsd-echo`, `mips-linux-gnu-echo`, `mips64-linux-gnueabi-echo`,
  `powerpc-linux-gnu-symexec-guess`, `powerpc32-linux-gnu-echo`,
  `x86-linux-gnu-echo`, `x86_64-linux-gnu-echo`.

### `elfutils/` — aosp-mirror/platform_external_elfutils
- Upstream: <https://github.com/aosp-mirror/platform_external_elfutils>
  (`tests/`), branch `master`. Files were stored `bzip2`-compressed upstream and
  are committed here decompressed.
- These are the reference `elfutils` test objects. They add architectures and
  object types not covered by the rizin set (AArch64, S/390(x), SPARC64, PPC64,
  RISC-V64; `ET_REL` `.o`, `ET_DYN` `.so`, `ET_CORE`, and a `.ko`).
- **License note:** `elfutils` is distributed under the GPLv3+/LGPLv3+. These
  compiled test objects are vendored solely as opaque parser test fixtures. If
  redistribution under this crate's MIT license is a concern, this subdirectory
  can be dropped without affecting the rizin set or the test harness (the tests
  iterate whatever `corpus.manifest` lists).

## The oracle: `corpus.manifest`

`corpus.manifest` is the expected-values oracle the tests assert `elfex` against.
It is produced by `generate_manifest.py`, an **independent** raw-ELF decoder that
shares no code with `elfex`. It records, per file: ELF class, byte order,
`e_machine`, `e_type`, entry point, program/section header counts, the
`DT_NEEDED` list, and the full section and program header tables (type, address,
size / vaddr, filesz, memsz, and section names).

The generator was cross-checked against GNU `readelf` (binutils) on
representative little- and big-endian files; `readelf` is the canonical field
oracle. It is used at *generation* time only, so the tests stay hermetic and
offline. (An earlier plan to consume LIEF's `.yaml` oracles was abandoned: the
`lief-project/samples` repository has been emptied and its replacement archive at
`data.romainthomas.fr/lief_tests.zip` returns 404.)

The `sha256` line in each block records the vendored file's digest so a
maintainer can detect corpus drift with a standard `sha256sum` check.

## Regenerating

After adding or replacing a file under `rizin/` or `elfutils/`:

```sh
cd tests/corpus
python3 generate_manifest.py > corpus.manifest
```

Then run `cargo test` to confirm `elfex` still agrees with the refreshed oracle.
