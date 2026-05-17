pub mod discover;
pub mod pair;
pub mod receive;
pub mod send;

use std::io::{self, BufRead, Write};

/// Read a single character from stdin (line-buffered, user types letter + Enter).
pub fn read_char() -> char {
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_ok() {
        line.chars().next().unwrap_or('r')
    } else {
        'r'
    }
}

/// Prompt the user with a question and read a single-char response.
pub fn prompt_choice(prompt: &str, choices: &str) -> char {
    print!("{prompt} [{choices}] ");
    let _ = io::stdout().flush();
    read_char()
}

/// Format a byte count as a human-readable string.
pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{b:.1} GB")
    } else if b >= MB {
        format!("{b:.1} MB")
    } else if b >= KB {
        format!("{b:.1} KB")
    } else {
        format!("{b} B")
    }
}
