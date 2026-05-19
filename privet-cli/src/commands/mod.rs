pub mod discover;
pub mod history;
pub mod pair;
pub mod receive;
pub mod send;

use std::io::{self, BufRead, Write};

use privet_core::TransferProgress;

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

/// Format a transfer progress update as a one-line status string.
pub fn format_progress_line(progress: &TransferProgress) -> String {
    format!(
        "\r  [{:.1}%] {:.1} MB/s  {:.1}/{:.1} MB",
        progress.percent(),
        progress.current_speed_bps / 1_000_000.0,
        progress.bytes_transferred as f64 / 1_000_000.0,
        progress.total_bytes as f64 / 1_000_000.0,
    )
}

/// Format a byte count as a human-readable string.
pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{b} B")
    }
}
