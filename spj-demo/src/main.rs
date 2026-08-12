//! Demo entry point. See the crate docs in `lib.rs` for what this
//! demonstrates; `run.sh` wraps this binary in `script` to capture a
//! replayable terminal session alongside the written artifacts.

use std::path::Path;

use spj_demo::narrate::Narrator;
use spj_demo::scenes;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let artifacts = Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    let narrator = Narrator::create(&artifacts)?;
    narrator.header(
        "STATIC PAYJOIN — recorded property demonstration",
        "regtest, in-process directory, real wire bytes",
    );

    let mut demo = scenes::setup(narrator).await?;
    scenes::s1_static_reuse::run(&mut demo).await?;
    scenes::s2_async_board::run(&mut demo).await?;
    scenes::s3_floor::run(&mut demo).await?;
    scenes::s4_token_upgrade::run(&mut demo).await?;

    demo.narrator.finish()?;
    Ok(())
}
