#![no_main]

use elfex::ElfHeaders;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ElfHeaders::from_slice(data);
});
