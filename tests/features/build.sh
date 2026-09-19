#!/usr/bin/env bash
# Builds the elfex ELF feature corpus from the toy sources in `src/`.
#
# The corpus targets feature *depth* on the two x86 ABIs: dynamic linking,
# relocation forms (RELA and REL), thread-local storage, indirect functions,
# static initialization, symbol versioning and visibility, hash styles, RELRO,
# debug and compressed-debug sections, and unlinked ET_REL objects.
#
# Outputs land in `bin/`. Run this only when regenerating the corpus; the tests
# read the committed binaries and never invoke a compiler.
#
# Determinism: build ids are content-derived (`--build-id=sha1`), source paths
# are normalized with `-ffile-prefix-map`, and SOURCE_DATE_EPOCH is pinned.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/src"
BIN="$HERE/bin"

export SOURCE_DATE_EPOCH=1700000000
export LC_ALL=C

mkdir -p "$BIN"
rm -f "$BIN"/*

CC=${CC:-gcc}
CXX=${CXX:-g++}
CLANG=${CLANG:-clang}

# Normalize paths embedded in debug info so output does not depend on checkout
# location.
NORM="-ffile-prefix-map=$SRC=src -gno-record-gcc-switches"
COMMON="-O1 -fno-asynchronous-unwind-tables $NORM"
BUILDID="-Wl,--build-id=sha1"

built=() skipped=()

# run <output> <description> <command...>
run() {
    local out="$1" desc="$2"
    shift 2
    if "$@" 2>"$BIN/.err"; then
        built+=("$out|$desc")
    else
        skipped+=("$out|$desc|$(tr '\n' ' ' <"$BIN/.err" | cut -c1-160)")
    fi
}

# ---------------------------------------------------------------------------
# x86-64 dynamic executables
# ---------------------------------------------------------------------------

run dyn_pie "PIE exe: RELATIVE+JUMP_SLOT, RELRO, init_array, visibilities, weak" \
    $CC $COMMON $BUILDID -o "$BIN/dyn_pie" "$SRC/dynamic.c"

run dyn_nopie "non-PIE exe: ET_EXEC at a fixed base, absolute relocations" \
    $CC $COMMON $BUILDID -no-pie -o "$BIN/dyn_nopie" "$SRC/dynamic.c"

run dyn_bindnow "DF_BIND_NOW + full RELRO" \
    $CC $COMMON $BUILDID -Wl,-z,now -Wl,-z,relro -o "$BIN/dyn_bindnow" "$SRC/dynamic.c"

run dyn_sysvhash "DT_HASH only (SysV hash style)" \
    $CC $COMMON $BUILDID -Wl,--hash-style=sysv -o "$BIN/dyn_sysvhash" "$SRC/dynamic.c"

run dyn_gnuhash "DT_GNU_HASH only" \
    $CC $COMMON $BUILDID -Wl,--hash-style=gnu -o "$BIN/dyn_gnuhash" "$SRC/dynamic.c"

run dyn_runpath "DT_RUNPATH (new dtags)" \
    $CC $COMMON $BUILDID -Wl,-rpath,/opt/elfex -Wl,--enable-new-dtags \
    -o "$BIN/dyn_runpath" "$SRC/dynamic.c"

run dyn_rpath "DT_RPATH (legacy dtags)" \
    $CC $COMMON $BUILDID -Wl,-rpath,/opt/elfex -Wl,--disable-new-dtags \
    -o "$BIN/dyn_rpath" "$SRC/dynamic.c"

run dyn_debug "DWARF .debug_* sections" \
    $CC $COMMON $BUILDID -g -o "$BIN/dyn_debug" "$SRC/dynamic.c"

run dyn_debug_compressed "SHF_COMPRESSED .debug_* sections" \
    $CC $COMMON $BUILDID -g -Wl,--compress-debug-sections=zlib \
    -o "$BIN/dyn_debug_compressed" "$SRC/dynamic.c"

run eh_frame_exe "unwind tables: .eh_frame + PT_GNU_EH_FRAME" \
    $CC -O1 $NORM $BUILDID -fasynchronous-unwind-tables \
    -o "$BIN/eh_frame_exe" "$SRC/dynamic.c"

run ifunc_dyn "STT_GNU_IFUNC + R_X86_64_IRELATIVE" \
    $CC $COMMON $BUILDID -o "$BIN/ifunc_dyn" "$SRC/ifunc.c"

run tls_exe "PT_TLS, .tdata/.tbss, local-exec TLS" \
    $CC $COMMON $BUILDID -o "$BIN/tls_exe" "$SRC/tls.c"

run cpp_exc "C++: .eh_frame, .gcc_except_table, vtables, guarded init_array" \
    $CXX -O1 $NORM $BUILDID -o "$BIN/cpp_exc" "$SRC/cpp_features.cpp"

run clang_dyn "alternative producer (clang) section layout" \
    $CLANG -O1 $NORM $BUILDID -o "$BIN/clang_dyn" "$SRC/dynamic.c"

# ---------------------------------------------------------------------------
# x86-64 static executables
# ---------------------------------------------------------------------------

run static_exe "static: no PT_DYNAMIC, no .dynsym" \
    $CC -Os $NORM $BUILDID -static -o "$BIN/static_exe" "$SRC/dynamic.c"

run static_pie "static-PIE: ET_DYN with dense R_X86_64_RELATIVE" \
    $CC -Os $NORM $BUILDID -static-pie -fPIE -o "$BIN/static_pie" "$SRC/dynamic.c"

# ---------------------------------------------------------------------------
# Shared objects
# ---------------------------------------------------------------------------

run libfeature.so "shared lib: DT_SONAME, version definitions, GD TLS" \
    $CC $COMMON $BUILDID -shared -fPIC -Wl,-soname,libfeature.so.1 \
    -Wl,--version-script,"$SRC/libfeature.map" \
    -o "$BIN/libfeature.so" "$SRC/shared.c"

run libfeature_nover.so "shared lib without a version script" \
    $CC $COMMON $BUILDID -shared -fPIC -o "$BIN/libfeature_nover.so" "$SRC/shared.c"

# ---------------------------------------------------------------------------
# Unlinked ET_REL objects (section-based relocation tables)
# ---------------------------------------------------------------------------

run reloc_x64.o "ET_REL x86-64: RELA with explicit addends" \
    $CC $COMMON -fPIC -c -o "$BIN/reloc_x64.o" "$SRC/reloc_object.c"

run tls_x64.o "ET_REL x86-64: unrelaxed general-dynamic TLS relocations" \
    $CC $COMMON -fPIC -c -o "$BIN/tls_x64.o" "$SRC/tls.c"

run cpp_comdat.o "ET_REL x86-64: SHT_GROUP COMDAT sections" \
    $CXX -O1 $NORM -fPIC -c -o "$BIN/cpp_comdat.o" "$SRC/cpp_features.cpp"

run libtls_ie.so "shared lib: initial-exec TLS -> R_X86_64_TPOFF64" \
    $CC $COMMON $BUILDID -shared -fPIC -o "$BIN/libtls_ie.so" "$SRC/tls_ie.c"

run libtls_ie_x86.so "i386 shared lib: initial-exec TLS -> R_386_TLS_TPOFF" \
    $CC $COMMON $BUILDID -m32 -shared -fPIC -o "$BIN/libtls_ie_x86.so" "$SRC/tls_ie.c"

# ---------------------------------------------------------------------------
# i386 (ELFCLASS32, EM_386) - REL relocation form with implicit addends
# ---------------------------------------------------------------------------

run reloc_x86.o "ET_REL i386: REL form, implicit addends, 8-bit type field" \
    $CC $COMMON -m32 -fPIC -c -o "$BIN/reloc_x86.o" "$SRC/reloc_object.c"

run dyn_x86 "i386 PIE exe: ELFCLASS32, .rel.dyn REL form" \
    $CC $COMMON $BUILDID -m32 -o "$BIN/dyn_x86" "$SRC/dynamic.c"

run tls_x86 "i386 PT_TLS" \
    $CC $COMMON $BUILDID -m32 -o "$BIN/tls_x86" "$SRC/tls.c"

run libfeature_x86.so "i386 shared lib: 32-bit dynamic relocations" \
    $CC $COMMON $BUILDID -m32 -shared -fPIC -Wl,-soname,libfeature32.so.1 \
    -o "$BIN/libfeature_x86.so" "$SRC/shared.c"

# ---------------------------------------------------------------------------
# Copy relocations (link against the shared objects built above)
# ---------------------------------------------------------------------------

run copy_reloc "non-PIE exe: R_X86_64_COPY for imported data" \
    $CC $COMMON $BUILDID -no-pie -o "$BIN/copy_reloc" "$SRC/copyreloc.c" \
    -L"$BIN" -lfeature -Wl,-rpath,'$ORIGIN'

run copy_reloc_x86 "non-PIE i386 exe: R_386_COPY for imported data" \
    $CC $COMMON $BUILDID -m32 -no-pie -o "$BIN/copy_reloc_x86" "$SRC/copyreloc.c" \
    -L"$BIN" -l:libfeature_x86.so -Wl,-rpath,'$ORIGIN'

# ---------------------------------------------------------------------------
# Post-processed variants
# ---------------------------------------------------------------------------

if [ -f "$BIN/dyn_debug" ]; then
    cp "$BIN/dyn_debug" "$BIN/dyn_stripped"
    if strip --strip-all "$BIN/dyn_stripped" 2>"$BIN/.err"; then
        built+=("dyn_stripped|stripped: no .symtab/.strtab")
    else
        skipped+=("dyn_stripped|stripped|$(tr '\n' ' ' <"$BIN/.err")")
        rm -f "$BIN/dyn_stripped"
    fi
fi

if [ -f "$BIN/dyn_debug" ]; then
    cp "$BIN/dyn_debug" "$BIN/dyn_debuglink"
    if objcopy --only-keep-debug "$BIN/dyn_debug" "$BIN/dyn_debuglink.debug" 2>/dev/null &&
        objcopy --strip-debug --add-gnu-debuglink="$BIN/dyn_debuglink.debug" \
            "$BIN/dyn_debuglink" 2>"$BIN/.err"; then
        rm -f "$BIN/dyn_debuglink.debug"
        built+=("dyn_debuglink|.gnu_debuglink section")
    else
        skipped+=("dyn_debuglink|.gnu_debuglink|$(tr '\n' ' ' <"$BIN/.err")")
        rm -f "$BIN/dyn_debuglink" "$BIN/dyn_debuglink.debug"
    fi
fi

rm -f "$BIN/.err"

echo "=== built (${#built[@]}) ==="
for entry in "${built[@]}"; do
    name="${entry%%|*}"
    desc="${entry#*|}"
    size=$(stat -c%s "$BIN/$name" 2>/dev/null || echo 0)
    printf '  %-24s %8s B  %s\n' "$name" "$size" "$desc"
done

if [ "${#skipped[@]}" -gt 0 ]; then
    echo "=== skipped (${#skipped[@]}) ==="
    for entry in "${skipped[@]}"; do
        printf '  %-24s %s\n' "${entry%%|*}" "${entry##*|}"
    done
fi

total=$(du -sb "$BIN" 2>/dev/null | cut -f1)
echo "=== corpus bytes: ${total:-unknown} ==="
