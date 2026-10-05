//! Records socket acceptance from setup until the observer is dropped.
#![allow(dead_code)]
use std::io;
use std::os::unix::net::UnixListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, RecvTimeoutError},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct AcquisitionObserver {
    events: Receiver<Result<(), io::Error>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AcquisitionObserver {
    pub fn new(listener: UnixListener) -> Self {
        listener
            .set_nonblocking(true)
            .expect("nonblocking acquisition observer");
        Self::observe(move || listener.accept().map(|_| ()))
    }

    pub fn tcp(listener: std::net::TcpListener) -> Self {
        listener
            .set_nonblocking(true)
            .expect("nonblocking TCP observer");
        Self::observe(move || listener.accept().map(|_| ()))
    }

    pub fn observe(mut accept: impl FnMut() -> io::Result<()> + Send + 'static) -> Self {
        let (tx, events) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = thread::spawn(move || {
            ready_tx.send(()).expect("observer owner is alive");
            while !stopped.load(Ordering::Acquire) {
                match accept() {
                    Ok(()) => {
                        if tx.send(Ok(())).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => {
                        let _ = tx.send(Err(error));
                        break;
                    }
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("observer armed");
        Self {
            events,
            stop,
            thread: Some(thread),
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<(), RecvTimeoutError> {
        match self.events.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => panic!("acquisition observer failed: {error}"),
            Err(RecvTimeoutError::Disconnected) => panic!("acquisition observer exited early"),
            Err(RecvTimeoutError::Timeout) => Err(RecvTimeoutError::Timeout),
        }
    }
}

impl Drop for AcquisitionObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self.thread.take().unwrap().join();
        if !thread::panicking() {
            result.expect("observer thread completed");
        }
    }
}
