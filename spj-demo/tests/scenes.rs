//! The six narrated scenes run on a fresh regtest node and every verdict,
//! each read back from the node, passes.

use std::time::Duration;

use spj_demo::narrate::Narrator;
use spj_demo::net::Error;
use spj_demo::scenes;

#[tokio::test(flavor = "multi_thread")]
async fn every_scene_passes() -> Result<(), Error> {
    let dir = tempfile::tempdir()?;
    let transcript = dir.path().join("transcript.txt");
    let mut demo = scenes::setup(Narrator::create(&transcript, Duration::ZERO)?).await?;
    scenes::run_all(&mut demo).await?;
    let verdicts = demo.n.verdicts();
    assert_eq!(verdicts, (1..=6).map(|scene| (scene, true)).collect::<Vec<_>>());
    let text = std::fs::read_to_string(&transcript)?;
    assert_eq!(text.matches("VERDICT [PASS]").count(), 6, "{text}");
    assert_eq!(demo.to_film.len(), 4, "scene 3's payjoin and scene 5's three");
    Ok(())
}
