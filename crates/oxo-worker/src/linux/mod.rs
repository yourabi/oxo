use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;

use magnus::value::ReprValue;
use magnus::{RArray, RModule, RString, Ruby, TryConvert, Value};
use oxo_core::{is_client_forwarding_header, normalize_header_name, DEFAULT_MAX_BODY_BYTES};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;
const QUEUE_CAPACITY: usize = 1024;
const READY_PREFIX: &str = "OXO_WORKER_READY=";

mod config;
mod frame;
mod parser;
mod ruby;
mod serve;

// Facade: exactly the pre-split surface consumed by lib.rs
// (`pub use linux::{main_entry, run_from_env, Config}`).
pub use config::Config;
pub use serve::{main_entry, run_from_env};

// Internal prelude: submodules do `use super::*;`, so the shared imports and
// consts above plus each sibling's pub(super) items resolve as they did in
// the single file. Nothing is exported beyond this module tree.
use self::parser::*;
use self::ruby::*;
use self::serve::*;
