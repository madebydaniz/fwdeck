#![no_main]

use libfuzzer_sys::fuzz_target;

// Both accepted definitions and typed parse failures must remain panic-free.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = fwdeck::infrastructure::firewalld::parse::parse_service_info(text);
    }
});
