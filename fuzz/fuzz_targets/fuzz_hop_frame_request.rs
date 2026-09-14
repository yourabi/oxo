//! Fuzz the request-frame decoder. Invariants: decoding ANY byte string never
//! panics (no unchecked index, no huge alloc — every length is validated before use);
//! and any successful decode is STABLE — re-encoding it and decoding again yields the
//! identical value (the tiling invariant guarantees a canonical form, so this catches
//! any decode that accepted a non-canonical or slack-bearing envelope).
#![no_main]

use oxo_core::hop_frame::{decode_request, encode_request, FrameCaps};
use libfuzzer_sys::fuzz_target;

fn caps() -> FrameCaps {
    FrameCaps {
        max_header_bytes: 64 * 1024,
        max_headers: 128,
        max_body_bytes: 1024 * 1024,
    }
}

fuzz_target!(|data: &[u8]| {
    // The fuzzer drives the ENVELOPE directly (the transport reads exactly this slice).
    if let Ok(req) = decode_request(data, &caps()) {
        // Re-encode: the envelope inside must tile exactly and re-decode identically.
        let frame = encode_request(&req).expect("a decoded request must re-encode");
        // Skip the 6-byte prefix to get the envelope back.
        let env = &frame[6..];
        let again = decode_request(env, &caps()).expect("canonical re-decode must succeed");
        assert_eq!(req, again, "decode is not stable under re-encode");
    }
});
