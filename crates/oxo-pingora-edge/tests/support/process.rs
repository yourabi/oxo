//! Bounded output capture and cleanup for test-owned Linux process trees.
#![allow(dead_code)]
use std::fs;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::process::{Child, ExitStatus, Output};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// Capture the descendants while the root is still owned/unreaped. The service
// gives its workers separate process groups, so killing just the root group is
// insufficient on an assertion failure. Never inspect arbitrary processes.
fn descendants(pid: u32, out: &mut Vec<u32>) {
    if let Ok(children) = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
        for child in children
            .split_whitespace()
            .filter_map(|p| p.parse::<u32>().ok())
        {
            descendants(child, out);
            out.push(child);
        }
    }
}

pub fn kill_tree(child: &mut Child) {
    let mut owned = Vec::new();
    descendants(child.id(), &mut owned);
    owned.push(child.id());
    for pid in owned {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl Capture {
    fn new<R: Read + AsRawFd + Send + 'static>(reader: Option<R>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let captured = bytes.clone();
        let thread = reader.map(|mut reader| {
            unsafe {
                let flags = libc::fcntl(reader.as_raw_fd(), libc::F_GETFL);
                assert!(
                    flags >= 0
                        && libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                            >= 0
                );
            }
            thread::spawn(move || {
                let mut buffer = [0; 4096];
                let mut final_reads = 0;
                loop {
                    if done.load(Ordering::Acquire) {
                        if final_reads == 16 {
                            break;
                        }
                        final_reads += 1;
                    }
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut saved = captured.lock().unwrap();
                            let keep = n.min((64 * 1024usize).saturating_sub(saved.len()));
                            saved.extend_from_slice(&buffer[..keep]);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if done.load(Ordering::Acquire) {
                                break;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })
        });
        Self {
            stop,
            thread,
            bytes,
        }
    }
    fn snapshot(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }
    fn finish(&mut self) -> Vec<u8> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("capture thread completed");
        }
        self.snapshot()
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.finish();
    }
}

pub struct CapturedChild {
    pub child: Child,
    stdout: Capture,
    stderr: Capture,
    reaped: bool,
}
impl CapturedChild {
    pub fn new(mut child: Child) -> Self {
        let stdout = Capture::new(child.stdout.take());
        let stderr = Capture::new(child.stderr.take());
        Self {
            child,
            stdout,
            stderr,
            reaped: false,
        }
    }
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn stdout(&self) -> Vec<u8> {
        self.stdout.snapshot()
    }
    pub fn stderr(&self) -> Vec<u8> {
        self.stderr.snapshot()
    }
    pub fn poll(&mut self) -> Option<ExitStatus> {
        let status = self.child.try_wait().expect("poll owned child");
        if status.is_some() {
            self.reaped = true;
        }
        status
    }
    pub fn wait(mut self, timeout: Duration) -> (Output, bool) {
        let deadline = Instant::now() + timeout;
        let (status, timed_out): (ExitStatus, bool) = loop {
            if let Some(status) = self.child.try_wait().expect("poll test child") {
                break (status, false);
            }
            if Instant::now() >= deadline {
                kill_tree(&mut self.child);
                break (self.child.wait().expect("reap timed-out child"), true);
            }
            thread::sleep(Duration::from_millis(10));
        };
        self.reaped = true;
        let stdout = self.stdout.finish();
        let stderr = self.stderr.finish();
        (
            Output {
                status,
                stdout,
                stderr,
            },
            timed_out,
        )
    }
}
impl Drop for CapturedChild {
    fn drop(&mut self) {
        if !self.reaped {
            kill_tree(&mut self.child);
        }
    }
}
