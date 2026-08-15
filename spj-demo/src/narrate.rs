//! Narrated transcript output.
//!
//! Every scene prints the same shape: a numbered title, the property it
//! claims to prove, the actions taken with their observable results,
//! and a verdict. The run is written to stdout and mirrored verbatim to
//! `artifacts/transcript.txt`, so the terminal recording and the
//! quotable text can never drift apart. Ledger tables are additionally
//! collected into `artifacts/ledgers.md` as standalone markdown.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const RULE: &str = "======================================================================";

pub struct Narrator {
    transcript: RefCell<File>,
    ledgers: RefCell<String>,
    ledgers_path: PathBuf,
}

impl Narrator {
    pub fn create(artifacts_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(artifacts_dir)?;
        let transcript = File::create(artifacts_dir.join("transcript.txt"))?;
        Ok(Self {
            transcript: RefCell::new(transcript),
            ledgers: RefCell::new(String::from("# Demo cost ledgers\n")),
            ledgers_path: artifacts_dir.join("ledgers.md"),
        })
    }

    fn emit(&self, line: &str) {
        println!("{line}");
        let mut transcript = self.transcript.borrow_mut();
        let _ = writeln!(transcript, "{line}");
        let _ = transcript.flush();
    }

    pub fn header(&self, title: &str, subtitle: &str) {
        self.emit(RULE);
        self.emit(&format!(" {title}"));
        self.emit(&format!(" {subtitle}"));
        self.emit(RULE);
    }

    pub fn scene(&self, number: u32, title: &str, claim: &str) {
        self.emit("");
        self.emit(RULE);
        self.emit(&format!(" SCENE {number} — {title}"));
        self.emit(RULE);
        for line in wrap(claim, 60) {
            self.emit(&format!("  CLAIM: {line}"));
        }
        self.emit("");
    }

    /// An action the demo takes, in one line of plain language.
    pub fn step(&self, text: &str) {
        for (i, line) in wrap(text, 64).iter().enumerate() {
            if i == 0 {
                self.emit(&format!("  * {line}"));
            } else {
                self.emit(&format!("    {line}"));
            }
        }
    }

    /// An observable result of the preceding step.
    pub fn result(&self, label: &str, value: &str) {
        self.emit(&format!("      {label}: {value}"));
    }

    pub fn note(&self, text: &str) {
        for line in wrap(text, 62) {
            self.emit(&format!("      | {line}"));
        }
    }

    pub fn verdict(&self, pass: bool, text: &str) {
        let mark = if pass { "PASS" } else { "FAIL" };
        self.emit("");
        for (i, line) in wrap(text, 56).iter().enumerate() {
            if i == 0 {
                self.emit(&format!("  VERDICT [{mark}]: {line}"));
            } else {
                self.emit(&format!("                 {line}"));
            }
        }
    }

    /// A cost accounting table, printed to the transcript and collected
    /// for `ledgers.md`.
    pub fn ledger(&self, title: &str, rows: &[(String, String)]) {
        let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        self.emit("");
        self.emit(&format!("      LEDGER — {title}"));
        for (k, v) in rows {
            self.emit(&format!("        {k:width$}  {v}"));
        }
        let mut md = self.ledgers.borrow_mut();
        md.push_str(&format!("\n## {title}\n\n| | |\n|---|---|\n"));
        for (k, v) in rows {
            md.push_str(&format!("| {k} | {v} |\n"));
        }
    }

    pub fn finish(&self) -> io::Result<()> {
        std::fs::write(&self.ledgers_path, self.ledgers.borrow().as_str())
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
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

#[cfg(test)]
mod tests {
    use super::wrap;

    #[test]
    fn wrap_splits_on_word_boundaries() {
        let lines = wrap("one two three four", 9);
        assert_eq!(lines, vec!["one two", "three", "four"]);
    }

    #[test]
    fn wrap_of_empty_text_yields_one_empty_line() {
        assert_eq!(wrap("", 10), vec![String::new()]);
    }
}
