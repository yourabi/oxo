use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub struct RawCase {
    pub name: &'static str,
    pub request: &'static [u8],
    pub status: u16,
}

pub fn send_uds_raw(socket: &Path, request: &[u8]) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect worker socket");
    stream.write_all(request).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();
    read_all_lossy(stream)
}

pub fn status(resp: &str) -> u16 {
    resp.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn body(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

pub fn s1_rejection_cases() -> &'static [RawCase] {
    &[
        RawCase {
            name: "transfer-encoding",
            request: b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "te-plus-content-length",
            request: b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "duplicate-host",
            request: b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "duplicate-content-length",
            request: b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
            status: 400,
        },
        RawCase {
            name: "obs-fold",
            request: b"GET / HTTP/1.1\r\nHost: x\r\n folded: y\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "bare-lf",
            request: b"GET / HTTP/1.1\nHost: x\n\n",
            status: 400,
        },
        RawCase {
            name: "bws-before-colon",
            request: b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "absolute-form",
            request: b"GET http://example.test/ HTTP/1.1\r\nHost: x\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "double-slash-target",
            request: b"GET //evil HTTP/1.1\r\nHost: x\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "expect",
            request: b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "connection-token",
            request: b"GET / HTTP/1.1\r\nHost: x\r\nConnection: x-smuggle\r\nX-Smuggle: yes\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "te-hop-header",
            request: b"GET / HTTP/1.1\r\nHost: x\r\nTE: trailers\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "keep-alive-hop-header",
            request: b"GET / HTTP/1.1\r\nHost: x\r\nKeep-Alive: timeout=5\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "upgrade-websocket",
            request: b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "trailers",
            request: b"POST / HTTP/1.1\r\nHost: x\r\nTrailer: x-later\r\nContent-Length: 0\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "grpc-content-type-unsupported-gap",
            request: b"POST /grpc.Service/Call HTTP/1.1\r\nHost: x\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\n\r\n",
            status: 400,
        },
        RawCase {
            name: "over-body-cap",
            request: b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n12345",
            status: 413,
        },
        RawCase {
            name: "short-body",
            request: b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n12",
            status: 400,
        },
        RawCase {
            name: "early-eof-head",
            request: b"GET / HTTP/1.1\r\nHost: x",
            status: 400,
        },
    ]
}

fn read_all_lossy(mut stream: UnixStream) -> String {
    let mut out = Vec::new();
    match stream.read_to_end(&mut out) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("read response: {e}"),
    }
    String::from_utf8_lossy(&out).into_owned()
}
