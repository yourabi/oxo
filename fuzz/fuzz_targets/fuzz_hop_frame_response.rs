//! Fuzz the response-frame decoder (the direction the EDGE consumes from a trusted
//! but verified worker). Same invariants as the request target: no panic on any input,
//! and stable re-encode/re-decode for any Ok.
#![no_main]

use oxo_core::hop_frame::{decode_response, encode_response, FrameCaps};
use libfuzzer_sys::fuzz_target;

fn caps() -> FrameCaps {
    FrameCaps {
        max_header_bytes: 64 * 1024,
        max_headers: 128,
        max_body_bytes: 64 * 1024 * 1024,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(resp) = decode_response(data, &caps()) {
        let frame = encode_response(&resp).expect("a decoded response must re-encode");
        let env = &frame[6..];
        let again = decode_response(env, &caps()).expect("canonical re-decode must succeed");
        assert_eq!(resp, again, "decode is not stable under re-encode");
    }
});
