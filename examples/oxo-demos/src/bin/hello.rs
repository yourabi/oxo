//! Thin binary: runs the hello demo and prints its narration.
//! `cargo run -p oxo-demos --bin hello` (needs `ruby` + the `rack` gem on PATH).

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    oxo_demos::run_hello_demo().await?;
    Ok(())
}
