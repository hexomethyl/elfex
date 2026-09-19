#!/usr/bin/env python3
"""Regenerate `features.manifest` from the compiled ELF feature corpus.

This is an *independent* ELF decoder: it shares no code with `elfex` and reads
the raw ident, header, section table, program table, dynamic array, symbol
tables, relocation tables, notes, and TLS header straight from each file's
bytes. Its output is the oracle that `tests/features.rs` asserts `elfex`
against. Cross-checked against GNU `readelf` (see PROVENANCE.md).

Where a value is derived rather than stored, this decoder reproduces `elfex`'s
documented definition independently:

  image_base = min(PT_LOAD.vaddr with memsz != 0) rounded down to `page`
  image_span = align_up(max(vaddr + memsz), page) - image_base
  page       = max(0x1000, max(PT_LOAD.p_align > 1))

Notes are read from PT_NOTE segments when present and from SHT_NOTE sections
otherwise, matching `ElfImage::notes`, so neither view double-counts a note.

Usage:  python3 generate_features_manifest.py > features.manifest
"""

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).parent
BIN = HERE / "bin"

SHT_RELA = 4
SHT_REL = 9
PT_LOAD = 1
PT_DYNAMIC = 2
PT_NOTE = 4
SHT_NOTE = 7
PT_TLS = 7
DT_NULL = 0
DT_NEEDED = 1
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
NT_GNU_BUILD_ID = 3

# Symbols whose full decode is pinned. Keeping this list explicit bounds the
# manifest: static binaries carry thousands of libc symbols whose exact values
# are toolchain-dependent and not what these tests are about.
PINNED_SYMBOLS = {
    # dynamic.c
    "visible_default", "visible_hidden", "visible_protected",
    "weak_function", "weak_data", "initialized_global", "zero_global",
    "rodata_message", "rodata_pointer", "function_table",
    # ifunc.c
    "picked",
    # tls.c
    "tls_initialized", "tls_zero", "tls_aligned",
    "tls_initial_exec", "tls_global_dynamic", "tls_sum",
    # shared.c
    "feature_v1", "feature_v2", "feature_counter", "feature_common",
    "feature_internal", "feature_tls", "feature_tls_get",
    # tls_ie.c
    "ie_counter", "ie_wide", "ie_bump",
    # reloc_object.c
    "use_everything", "local_data", "static_data", "literal",
    "data_pointer", "func_pointer", "external_symbol", "external_function",
    "main",
}


def u(data, off, size, le):
    return int.from_bytes(data[off:off + size], "little" if le else "big")


def i64(value):
    """Reinterprets an unsigned 64-bit addend as signed."""
    return value - (1 << 64) if value >= (1 << 63) else value


def i32(value):
    return value - (1 << 32) if value >= (1 << 31) else value


def align_up(value, alignment):
    if alignment <= 1:
        return value
    remainder = value % alignment
    return value if remainder == 0 else value + (alignment - remainder)


def cstr(blob, offset):
    if offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    end = len(blob) if end < 0 else end
    return blob[offset:end].decode("latin-1")


class Elf:
    def __init__(self, path):
        self.path = path
        b = path.read_bytes()
        self.b = b
        assert b[:4] == b"\x7fELF", f"{path}: not an ELF file"
        self.ei_class = b[4]
        self.ei_data = b[5]
        self.osabi = b[7]
        self.le = self.ei_data == 1
        self.is64 = self.ei_class == 2
        le, is64 = self.le, self.is64

        self.e_type = u(b, 16, 2, le)
        self.e_machine = u(b, 18, 2, le)
        if is64:
            self.e_entry = u(b, 24, 8, le)
            e_phoff, e_shoff = u(b, 32, 8, le), u(b, 40, 8, le)
            e_phentsize, e_phnum = u(b, 54, 2, le), u(b, 56, 2, le)
            e_shentsize, e_shnum = u(b, 58, 2, le), u(b, 60, 2, le)
            e_shstrndx = u(b, 62, 2, le)
        else:
            self.e_entry = u(b, 24, 4, le)
            e_phoff, e_shoff = u(b, 28, 4, le), u(b, 32, 4, le)
            e_phentsize, e_phnum = u(b, 42, 2, le), u(b, 44, 2, le)
            e_shentsize, e_shnum = u(b, 46, 2, le), u(b, 48, 2, le)
            e_shstrndx = u(b, 50, 2, le)
        self.phnum, self.shnum = e_phnum, e_shnum

        # Program headers.
        self.segments = []
        for index in range(e_phnum):
            base = e_phoff + index * e_phentsize
            if is64:
                self.segments.append({
                    "type": u(b, base, 4, le), "flags": u(b, base + 4, 4, le),
                    "offset": u(b, base + 8, 8, le), "vaddr": u(b, base + 16, 8, le),
                    "filesz": u(b, base + 32, 8, le), "memsz": u(b, base + 40, 8, le),
                    "align": u(b, base + 48, 8, le),
                })
            else:
                self.segments.append({
                    "type": u(b, base, 4, le), "offset": u(b, base + 4, 4, le),
                    "vaddr": u(b, base + 8, 4, le), "filesz": u(b, base + 16, 4, le),
                    "memsz": u(b, base + 20, 4, le), "flags": u(b, base + 24, 4, le),
                    "align": u(b, base + 28, 4, le),
                })

        # Section headers.
        self.sections = []
        for index in range(e_shnum):
            base = e_shoff + index * e_shentsize
            if is64:
                self.sections.append({
                    "nameoff": u(b, base, 4, le), "type": u(b, base + 4, 4, le),
                    "flags": u(b, base + 8, 8, le), "addr": u(b, base + 16, 8, le),
                    "offset": u(b, base + 24, 8, le), "size": u(b, base + 32, 8, le),
                    "link": u(b, base + 40, 4, le), "entsize": u(b, base + 56, 8, le),
                })
            else:
                self.sections.append({
                    "nameoff": u(b, base, 4, le), "type": u(b, base + 4, 4, le),
                    "flags": u(b, base + 8, 4, le), "addr": u(b, base + 12, 4, le),
                    "offset": u(b, base + 16, 4, le), "size": u(b, base + 20, 4, le),
                    "link": u(b, base + 24, 4, le), "entsize": u(b, base + 36, 4, le),
                })

        shstr = b""
        if e_shnum and e_shstrndx < e_shnum:
            head = self.sections[e_shstrndx]
            shstr = b[head["offset"]:head["offset"] + head["size"]]
        for section in self.sections:
            section["name"] = cstr(shstr, section["nameoff"])

    # -- derived geometry -------------------------------------------------

    def geometry(self):
        page = 0x1000
        min_vaddr, max_end = None, 0
        for segment in self.segments:
            if segment["type"] != PT_LOAD or segment["memsz"] == 0:
                continue
            vaddr = segment["vaddr"]
            min_vaddr = vaddr if min_vaddr is None else min(min_vaddr, vaddr)
            max_end = max(max_end, vaddr + segment["memsz"])
            if segment["align"] > 1:
                page = max(page, segment["align"])
        if min_vaddr is None:
            return 0, 0
        base = min_vaddr - (min_vaddr % page)
        return base, align_up(max_end, page) - base

    def section_data(self, section):
        if section["type"] == 8:  # SHT_NOBITS occupies no file bytes
            return b""
        return self.b[section["offset"]:section["offset"] + section["size"]]

    def find_section(self, name):
        return next((s for s in self.sections if s["name"] == name), None)

    # -- derived tables ---------------------------------------------------

    def dynamic(self):
        """Decodes the PT_DYNAMIC array, stopping before DT_NULL."""
        segment = next((s for s in self.segments if s["type"] == PT_DYNAMIC), None)
        if segment is None:
            return []
        size = 16 if self.is64 else 8
        width = 8 if self.is64 else 4
        data = self.b[segment["offset"]:segment["offset"] + segment["filesz"]]
        entries = []
        for off in range(0, len(data) - size + 1, size):
            tag = u(data, off, width, self.le)
            val = u(data, off + width, width, self.le)
            if tag == DT_NULL:
                break
            entries.append((tag, val))
        return entries

    def dynstr(self):
        section = self.find_section(".dynstr")
        return self.section_data(section) if section else b""

    def symbols(self, table_name, strtab_name):
        section = self.find_section(table_name)
        if section is None:
            return []
        strtab_section = self.find_section(strtab_name)
        strtab = self.section_data(strtab_section) if strtab_section else b""
        data = self.section_data(section)
        size = 24 if self.is64 else 16
        out = []
        for off in range(0, len(data) - size + 1, size):
            if self.is64:
                nameoff = u(data, off, 4, self.le)
                info, other = data[off + 4], data[off + 5]
                shndx = u(data, off + 6, 2, self.le)
                value, sym_size = u(data, off + 8, 8, self.le), u(data, off + 16, 8, self.le)
            else:
                nameoff = u(data, off, 4, self.le)
                value, sym_size = u(data, off + 4, 4, self.le), u(data, off + 8, 4, self.le)
                info, other = data[off + 12], data[off + 13]
                shndx = u(data, off + 14, 2, self.le)
            out.append({
                "name": cstr(strtab, nameoff), "value": value, "size": sym_size,
                "bind": info >> 4, "type": info & 0xF, "vis": other & 0x3,
                "shndx": shndx,
            })
        return out

    def relocations(self):
        """Decodes every SHT_REL/SHT_RELA section, in section-table order."""
        tables = []
        for section in self.sections:
            if section["type"] == SHT_RELA:
                is_rela = True
            elif section["type"] == SHT_REL:
                is_rela = False
            else:
                continue
            data = self.section_data(section)
            if self.is64:
                size = 24 if is_rela else 16
            else:
                size = 12 if is_rela else 8
            width = 8 if self.is64 else 4
            entries = []
            for off in range(0, len(data) - size + 1, size):
                offset = u(data, off, width, self.le)
                info = u(data, off + width, width, self.le)
                if self.is64:
                    sym, rtype = info >> 32, info & 0xFFFF_FFFF
                else:
                    sym, rtype = info >> 8, info & 0xFF
                addend = None
                if is_rela:
                    raw = u(data, off + 2 * width, width, self.le)
                    addend = i64(raw) if self.is64 else i32(raw)
                entries.append((offset, sym, rtype, addend))
            tables.append((section["name"], is_rela, entries))
        return tables

    @staticmethod
    def _parse_notes(data, le):
        """Decodes a note block: namesz/descsz/type, each padded to 4 bytes."""
        out = []
        off = 0
        while len(data) - off >= 12:
            namesz = u(data, off, 4, le)
            descsz = u(data, off + 4, 4, le)
            ntype = u(data, off + 8, 4, le)
            name_start = off + 12
            desc_start = name_start + align_up(namesz, 4)
            desc_end = desc_start + descsz
            if desc_end > len(data):
                break
            name = data[name_start:name_start + namesz].rstrip(b"\0").decode("latin-1")
            out.append((name, ntype, data[desc_start:desc_end]))
            off = desc_start + align_up(descsz, 4)
        return out

    def notes(self):
        """Decodes notes from PT_NOTE segments, or SHT_NOTE sections when the
        object has no note segment. The two views describe the same bytes in a
        linked object, so only one is used and no note is counted twice."""
        segments = [s for s in self.segments if s["type"] == PT_NOTE]
        if segments:
            out = []
            for segment in segments:
                data = self.b[segment["offset"]:segment["offset"] + segment["filesz"]]
                out.extend(self._parse_notes(data, self.le))
            return out
        out = []
        for section in self.sections:
            if section["type"] == SHT_NOTE:
                out.extend(self._parse_notes(self.section_data(section), self.le))
        return out

    def tls(self):
        segment = next((s for s in self.segments if s["type"] == PT_TLS), None)
        if segment is None:
            return None
        return (segment["vaddr"], segment["filesz"], segment["memsz"], segment["align"])


def emit(path, out):
    elf = Elf(path)
    base, span = elf.geometry()
    dynstr = elf.dynstr()
    dynamic = elf.dynamic()

    out.append(f"file {path.relative_to(HERE).as_posix()}")
    out.append(f"sha256 {hashlib.sha256(elf.b).hexdigest()}")
    out.append(f"class {64 if elf.is64 else 32}")
    out.append(f"endian {'little' if elf.le else 'big'}")
    out.append(f"osabi {elf.osabi}")
    out.append(f"type {elf.e_type}")
    out.append(f"machine {elf.e_machine}")
    out.append(f"entry {elf.e_entry}")
    out.append(f"phnum {elf.phnum}")
    out.append(f"shnum {elf.shnum}")
    out.append(f"imagebase {base}")
    out.append(f"imagespan {span}")

    for index, segment in enumerate(elf.segments):
        out.append(
            f"seg {index} {segment['type']} {segment['vaddr']} {segment['filesz']} "
            f"{segment['memsz']} {segment['flags']} {segment['align']}"
        )
    for index, section in enumerate(elf.sections):
        out.append(
            f"sec {index} {section['type']} {section['addr']} {section['size']} "
            f"{section['flags']} {section['entsize']} \"{section['name']}\""
        )

    for tag, value in dynamic:
        out.append(f"dyn {tag} {value}")
    for tag, value in dynamic:
        if tag == DT_NEEDED:
            out.append(f"needed \"{cstr(dynstr, value)}\"")
    for tag, value in dynamic:
        if tag == DT_SONAME:
            out.append(f"soname \"{cstr(dynstr, value)}\"")
        elif tag == DT_RUNPATH:
            out.append(f"runpath \"{cstr(dynstr, value)}\"")
        elif tag == DT_RPATH:
            out.append(f"rpath \"{cstr(dynstr, value)}\"")

    tls = elf.tls()
    if tls is not None:
        out.append(f"tls {tls[0]} {tls[1]} {tls[2]} {tls[3]}")

    for name, ntype, desc in elf.notes():
        out.append(f"note \"{name}\" {ntype} {len(desc)}")
        if name == "GNU" and ntype == NT_GNU_BUILD_ID:
            out.append(f"buildid {desc.hex()}")

    # Relocation tables in section order, plus an aggregate type histogram.
    histogram = {}
    for name, is_rela, entries in elf.relocations():
        out.append(f"reltab \"{name}\" {1 if is_rela else 0} {len(entries)}")
        for _, _, rtype, _ in entries:
            histogram[rtype] = histogram.get(rtype, 0) + 1
    for rtype in sorted(histogram):
        out.append(f"reltype {rtype} {histogram[rtype]}")

    # First entry of each relocation table pins offset/symbol/type/addend decode.
    for name, is_rela, entries in elf.relocations():
        if entries:
            offset, sym, rtype, addend = entries[0]
            addend_text = "none" if addend is None else str(addend)
            out.append(f"rel0 \"{name}\" {offset} {sym} {rtype} {addend_text}")

    for label, table_name, strtab_name in (
        ("symtab", ".symtab", ".strtab"),
        ("dynsym", ".dynsym", ".dynstr"),
    ):
        symbols = elf.symbols(table_name, strtab_name)
        out.append(f"{label} {len(symbols)}")
        binds, types, visibilities = {}, {}, {}
        for symbol in symbols:
            binds[symbol["bind"]] = binds.get(symbol["bind"], 0) + 1
            types[symbol["type"]] = types.get(symbol["type"], 0) + 1
            visibilities[symbol["vis"]] = visibilities.get(symbol["vis"], 0) + 1
        for key in sorted(binds):
            out.append(f"symbind {label} {key} {binds[key]}")
        for key in sorted(types):
            out.append(f"symtype {label} {key} {types[key]}")
        for key in sorted(visibilities):
            out.append(f"symvis {label} {key} {visibilities[key]}")
        seen = set()
        for symbol in symbols:
            name = symbol["name"]
            if name in PINNED_SYMBOLS and name not in seen:
                seen.add(name)
                out.append(
                    f"sym {label} \"{name}\" {symbol['value']} {symbol['size']} "
                    f"{symbol['bind']} {symbol['type']} {symbol['vis']} {symbol['shndx']}"
                )

    out.append("")


def main():
    files = sorted(p for p in BIN.iterdir() if p.is_file())
    if not files:
        sys.exit("no files in bin/; run build.sh first")
    out = [
        "# Auto-generated by generate_features_manifest.py. Do not edit by hand.",
        "# Oracle for the elfex feature-corpus tests: an independent raw-ELF",
        "# decode of each compiled fixture, cross-checked against GNU readelf.",
        "# Numbers are decimal. Records appear in table order.",
        "",
    ]
    for path in files:
        emit(path, out)
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()
