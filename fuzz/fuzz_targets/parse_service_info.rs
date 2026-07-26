#![no_main]

use libfuzzer_sys::fuzz_target;

// `parse_service_info` parses `firewall-cmd --info-service` output into a
// `ServiceDefinition` with no `Result`; a panic is the only failure mode.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = fwdeck::infrastructure::firewalld::parse::parse_service_info(text);
    }
});
