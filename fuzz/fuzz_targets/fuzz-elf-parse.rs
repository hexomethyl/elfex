#![no_main]

use elfex::{ElfFile, ElfImage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = ElfImage::parse(data) {
        let _ = image.dynamic();
        let _ = image.symbols();
        let _ = image.dynamic_symbols();
        let _ = image.relocations();
        let _ = image.notes();
        let _ = image.build_id();
        let _ = image.tls();
        let _ = image.needed_libraries();
        let _ = image.validate();
        let _ = image.try_build();
    }
    let _ = ElfImage::parse_mapped(data);
    let _ = ElfFile::parse(data);
});
