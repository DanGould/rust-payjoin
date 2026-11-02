//! The narrated transcript of a demo run.
//!
//! Each line names who acts and what they see, with `[ok]` on a line that
//! reports a check. A scene ends in one `VERDICT [PASS]` or `VERDICT [FAIL]`
//! line, which the caller decides from the node's state. Everything printed
//! is also written to a transcript file, so the recorded terminal and the
//! quotable text say the same thing.

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

const RULE: &str =
    "==========================================================================================";
const WIDTH: usize = 104;
const SPEAKER: usize = 11;

pub struct Narrator {
    transcript: RefCell<File>,
    /// A pause after each line, so a recorded terminal can be read as it plays.
    pace: Duration,
    verdicts: RefCell<Vec<(u32, bool)>>,
    scene: Cell<u32>,
}

impl Narrator {
    pub fn create(transcript: &Path, pace: Duration) -> io::Result<Self> {
        if let Some(dir) = transcript.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            transcript: RefCell::new(File::create(transcript)?),
            pace,
            verdicts: RefCell::new(Vec::new()),
            scene: Cell::new(0),
        })
    }

    fn emit(&self, line: &str) {
        println!("{line}");
        let mut transcript = self.transcript.borrow_mut();
        let _ = writeln!(transcript, "{line}");
        let _ = transcript.flush();
        if !self.pace.is_zero() {
            std::thread::sleep(self.pace);
        }
    }

    pub fn header(&self, title: &str, subtitle: &str) {
        self.emit(RULE);
        self.emit(&format!(" {title}"));
        self.emit(&format!(" {subtitle}"));
        self.emit(RULE);
    }

    pub fn scene(&self, number: u32, title: &str) {
        self.scene.set(number);
        self.emit("");
        self.emit(&format!("=== {number}. {title}"));
    }

    /// A line spoken by `who`.
    pub fn say(&self, who: &str, text: &str) {
        let prefix = format!("{who:>SPEAKER$}: ");
        let indent = " ".repeat(prefix.len());
        for (i, line) in wrap(text, WIDTH - prefix.len()).iter().enumerate() {
            self.emit(&format!("{}{line}", if i == 0 { &prefix } else { &indent }));
        }
    }

    /// A line reporting a check, marked `[ok]` when it holds. Returns `ok`.
    pub fn check(&self, who: &str, text: &str, ok: bool) -> bool {
        self.say(who, &format!("{text} {}", if ok { "[ok]" } else { "[FAILED]" }));
        ok
    }

    pub fn why(&self, text: &str) { self.say("Why", text); }

    /// The scene's verdict.
    pub fn verdict(&self, pass: bool, text: &str) {
        self.verdicts.borrow_mut().push((self.scene.get(), pass));
        let mark = if pass { "PASS" } else { "FAIL" };
        let prefix = format!("  VERDICT [{mark}]: ");
        let indent = " ".repeat(prefix.len());
        for (i, line) in wrap(text, WIDTH - prefix.len()).iter().enumerate() {
            self.emit(&format!("{}{line}", if i == 0 { &prefix } else { &indent }));
        }
    }

    /// Every verdict so far, by scene number.
    pub fn verdicts(&self) -> Vec<(u32, bool)> { self.verdicts.borrow().clone() }

    pub fn line(&self, text: &str) { self.emit(text); }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

/// A long hex string shortened to its ends, as the transcript shows keys and
/// txids.
pub fn short(hex: &str) -> String {
    if hex.len() <= 16 {
        return hex.to_string();
    }
    format!("{}…{}", &hex[..10], &hex[hex.len() - 6..])
}

/// Satoshis with thousands separators.
pub fn sats(amount: bitcoin::Amount) -> String {
    let digits = amount.to_sat().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    format!("{out} sat")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_splits_on_word_boundaries() {
        assert_eq!(wrap("one two three four", 9), vec!["one two", "three", "four"]);
        assert_eq!(wrap("", 10), vec![String::new()]);
    }

    #[test]
    fn amounts_and_hex_read_easily() {
        assert_eq!(sats(bitcoin::Amount::from_sat(1_234_567)), "1,234,567 sat");
        assert_eq!(sats(bitcoin::Amount::from_sat(999)), "999 sat");
        assert_eq!(short("0123456789abcdef0123"), "0123456789…ef0123");
    }
}
