// M-A: the counting allocator must be registered at the binary root (one per binary).
// Bench-only feature; the shipped default build contains no counter and no wrapper.
#[cfg(feature = "alloc-count")]
#[global_allocator]
static COUNTING_ALLOC: oxo_pingora_edge::alloc_count::CountingSystemAlloc =
    oxo_pingora_edge::alloc_count::CountingSystemAlloc;

fn main() {
    // build-identity census: the version-baseline driver greps this line and
    // REFUSES any cell whose realized identity mismatches the staged intent (the
    // staged-vs-running divergence class). Values embedded at compile time (build.rs).
    eprintln!(
        "oxo-edge: census pingora={} source={} tree={} rustc={}",
        env!("OXO_BUILD_PINGORA_VERSION"),
        env!("OXO_BUILD_PINGORA_SOURCE"),
        env!("OXO_BUILD_TREE"),
        env!("OXO_BUILD_RUSTC"),
    );
    if let Err(err) = oxo_pingora_edge::fail_closed_main() {
        eprintln!("{err}");
        std::process::exit(78);
    }
}
