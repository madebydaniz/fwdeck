#![no_main]

use libfuzzer_sys::fuzz_target;

// `parse_list_all_zones` consumes raw `firewall-cmd --list-all-zones` output and
// returns (parsed, degraded) with no `Result` — a panic is its only failure
// mode. FWDeck promises never to panic on daemon output, so fuzz it.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = fwdeck::infrastructure::firewalld::parse::parse_list_all_zones(text);
    }
});
