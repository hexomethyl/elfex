In#!/usr/bin/env bash
set -euo pipefail

# Directory layout
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MELKOR_DIR="$SCRIPT_DIR/Melkor_ELF_Fuzzer"

# Mutation count (override via COUNT env var)
COUNT="${COUNT:-500}"

# Corpus output directories
CORPUS_PARSE="$FUZZ_DIR/corpus/fuzz-elf-parse"
CORPUS_HEADERS="$FUZZ_DIR/corpus/fuzz-elf-headers"
mkdir -p "$CORPUS_PARSE" "$CORPUS_HEADERS"

# Temp directory for seed ELF generation
WORK_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Clone Melkor if not already present
if [ ! -d "$MELKOR_DIR" ]; then
    echo "[*] Cloning Melkor ELF Fuzzer..."
    git clone https://github.com/IOActive/Melkor_ELF_Fuzzer.git "$MELKOR_DIR"
fi

# Build Melkor (add -fcommon for GCC >= 10 tentative-definition compat)
echo "[*] Building Melkor..."
make -C "$MELKOR_DIR" CFLAGS="-ggdb -Wall -fcommon"

# Create a tiny seed ELF
TMP_C="$WORK_DIR/seed.c"
cat > "$TMP_C" << 'EOF'
int main(void) { return 0; }
EOF

SEEDS=()

SEED="$WORK_DIR/seed_elf64"
echo "[*] Compiling 64-bit seed ELF..."
gcc -o "$SEED" "$TMP_C"
SEEDS+=("$SEED")

SEED32="$WORK_DIR/seed_elf32"
if gcc -m32 -o "$SEED32" "$TMP_C" 2>/dev/null; then
    echo "[*] Compiled 32-bit seed ELF."
    SEEDS+=("$SEED32")
else
    echo "[!] 32-bit compilation not available, skipping."
fi

rm -f "$TMP_C"

# Run Melkor on each seed ELF
TOTAL=0
for seed in "${SEEDS[@]}"; do
    seed_name="$(basename "$seed")"
    echo "[*] Running Melkor on $seed_name with -A -n $COUNT..."

    # Melkor creates orcs_* directories in the current working directory
    pushd "$WORK_DIR" > /dev/null
    # Melkor may crash on architecture-mismatched seeds; tolerate it
    "$MELKOR_DIR/melkor" -A -n "$COUNT" "$seed" || echo "[!] Melkor exited with status $? on $seed_name (partial corpus may still be usable)"
    popd > /dev/null

    # Copy all generated orcs into both corpus directories
    for orcs_dir in "$WORK_DIR"/orcs_*; do
        [ -d "$orcs_dir" ] || continue
        count_before=$TOTAL
        for orc in "$orcs_dir"/*; do
            [ -f "$orc" ] || continue
            base="$(basename "$orc")"
            cp "$orc" "$CORPUS_PARSE/${seed_name}_${base}"
            cp "$orc" "$CORPUS_HEADERS/${seed_name}_${base}"
            TOTAL=$((TOTAL + 1))
        done
        echo "[*] Copied $((TOTAL - count_before)) files from $(basename "$orcs_dir")"
    done

    # Clean up orcs directories for this seed
    rm -rf "$WORK_DIR"/orcs_*
done

# Copy original seed ELFs into corpus directories
for seed in "${SEEDS[@]}"; do
    seed_name="$(basename "$seed")"
    cp "$seed" "$CORPUS_PARSE/$seed_name"
    cp "$seed" "$CORPUS_HEADERS/$seed_name"
    TOTAL=$((TOTAL + 1))
done

echo "[+] Done. $TOTAL corpus files generated in:"
echo "    $CORPUS_PARSE"
echo "    $CORPUS_HEADERS"
