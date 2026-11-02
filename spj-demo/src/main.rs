//! Run the six narrated silent payjoin scenes on a fresh regtest node.
//!
//! ```text
//! spj-demo [--transcript PATH] [--pace MS] [--video DIR]
//! ```
//!
//! `--transcript` mirrors the narration to a file (default
//! `target/spj-demo/transcript.txt`). `--pace` pauses after each line so a
//! terminal recording can be read as it plays. `--video` films the silent
//! payjoins of scenes 3 and 5 in a local mempool explorer before the node
//! stops; see `video/record-tx.sh` for what that needs. The exit status is 0
//! only if every scene's verdict passed.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use spj_demo::narrate::Narrator;
use spj_demo::net::Error;
use spj_demo::scenes;
use spj_demo::video::{self, Node};

struct Args {
    transcript: PathBuf,
    pace: Duration,
    video: Option<PathBuf>,
}

fn args() -> Result<Args, Error> {
    let mut args = Args {
        transcript: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/spj-demo/transcript.txt"),
        pace: Duration::ZERO,
        video: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--transcript" => args.transcript = value()?.into(),
            "--pace" => args.pace = Duration::from_millis(value()?.parse()?),
            "--video" => args.video = Some(value()?.into()),
            _ => return Err(format!("unknown argument {flag}").into()),
        }
    }
    Ok(args)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<ExitCode, Error> {
    let args = args()?;
    let narrator = Narrator::create(&args.transcript, args.pace)?;
    let mut demo = scenes::setup(narrator).await?;
    scenes::run_all(&mut demo).await?;

    let verdicts = demo.n.verdicts();
    let passed = verdicts.iter().filter(|(_, pass)| *pass).count();
    demo.n.line("");
    demo.n.line(&format!("{passed} of {} scenes passed", verdicts.len()));

    if let Some(dir) = args.video {
        std::fs::create_dir_all(&dir)?;
        let node = Node::from(&demo.regtest.node);
        for (label, txid) in &demo.to_film {
            let out = dir.join(format!("{label}.mp4"));
            demo.n.line(&format!("filming {txid} to {}", out.display()));
            let node = node.clone();
            let (txid, path) = (*txid, out.clone());
            tokio::task::spawn_blocking(move || video::record_tx(&node, txid, &path)).await??;
        }
    }
    Ok(if passed == 6 && verdicts.len() == 6 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
