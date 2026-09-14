// the build-identity census. Embeds, at compile time, exactly what a
// version-vs-version benchmark must be able to verify at runtime: which Pingora
// the binary was really built against (version + source), the oxo tree it came
// from, and the compiler. The edge announces these at startup; the baseline driver
// REFUSES any cell whose realized identity mismatches (the staged-vs-running trap).
use std::path::Path;
use std::process::Command;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let ws_root = Path::new(&manifest).join("../..");

    // Pingora version + source, straight from the resolved lockfile.
    let lock = std::fs::read_to_string(ws_root.join("Cargo.lock")).unwrap_or_default();
    let mut version = "unknown".to_string();
    let mut source = "unknown".to_string();
    let mut lines = lock.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"pingora\"" {
            for follow in lines.by_ref() {
                if let Some(v) = follow.trim().strip_prefix("version = \"") {
                    version = v.trim_end_matches('"').to_string();
                } else if let Some(s) = follow.trim().strip_prefix("source = \"") {
                    source = s.trim_end_matches('"').to_string();
                } else if follow.trim().is_empty() || follow.starts_with("[[") {
                    break;
                }
            }
            // A path-patched crate has NO source line in the lock.
            if source == "unknown" {
                source = "path-patch".to_string();
            }
            break;
        }
    }

    let git = |args: &[&str]| -> String {
        Command::new("git")
            .args(args)
            .current_dir(&ws_root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    };
    // Best-effort: guests build from tarred trees (no .git) and linked worktrees
    // confuse cross-OS git -- "unknown" is an honest value there; the load-bearing
    // refusal fields are the pingora version/source and the compiler.
    let mut tree = git(&["rev-parse", "--short=12", "HEAD"]);
    if tree != "unknown" {
        let status = git(&["status", "--porcelain", "--untracked-files=no"]);
        if status != "unknown" && !status.is_empty() {
            tree.push_str("+dirty");
        }
    }
    let rustc = std::env::var("RUSTC")
        .ok()
        .and_then(|rc| Command::new(rc).arg("--version").output().ok())
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=OXO_BUILD_PINGORA_VERSION={version}");
    println!("cargo:rustc-env=OXO_BUILD_PINGORA_SOURCE={source}");
    println!("cargo:rustc-env=OXO_BUILD_TREE={tree}");
    println!("cargo:rustc-env=OXO_BUILD_RUSTC={rustc}");
    // Re-run when the resolution or tree state changes.
    println!(
        "cargo:rerun-if-changed={}",
        ws_root.join("Cargo.lock").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ws_root.join(".git/HEAD").display()
    );
}
