//! Demo entry point. See the crate docs in `lib.rs` for what this
//! demonstrates; `run.sh` wraps this binary in `script` to capture a
//! replayable terminal session alongside the written artifacts.

use std::path::Path;

use spj_demo::narrate::Narrator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let artifacts = Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    let narrator = Narrator::create(&artifacts)?;
    narrator.header(
        "STATIC PAYJOIN — recorded property demonstration",
        "regtest, in-process directory, real wire bytes",
    );
    narrator.finish()?;
    Ok(())
}
