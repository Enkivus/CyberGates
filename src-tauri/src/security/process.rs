use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::error::{AppError, AppResult};

const MAX_CAPTURE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CommandOutput {
    pub fn combined(&self) -> String {
        let mut out = self.stdout.trim().to_string();
        if out.is_empty() {
            out = self.stderr.trim().to_string();
        }
        out
    }

    pub fn first_line(&self) -> String {
        self.combined().lines().next().unwrap_or_default().trim().to_string()
    }
}

/// Execute a program directly (never through a shell) with a hard timeout and
/// bounded output capture. Arguments are passed as an array, not concatenated.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> AppResult<CommandOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|err| {
        AppError::Internal(format!("could not start {program}: {err}"))
    })?;

    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
        Err(err) => {
            let _ = child.kill();
            return Err(AppError::Internal(format!(
                "failed while waiting for {program}: {err}"
            )));
        }
    };

    let stdout = read_bounded(child.stdout.take());
    let stderr = read_bounded(child.stderr.take());

    Ok(CommandOutput {
        success: status.map(|s| s.success()).unwrap_or(false),
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        timed_out: status.is_none(),
    })
}

fn read_bounded<R: Read>(reader: Option<R>) -> String {
    let Some(reader) = reader else {
        return String::new();
    };
    let mut buffer = Vec::new();
    let _ = reader.take(MAX_CAPTURE_BYTES).read_to_end(&mut buffer);
    String::from_utf8_lossy(&buffer).to_string()
}

pub fn command_exists(program: &str) -> bool {
    which::which(program).is_ok()
}

pub fn run_optional(program: &str, args: &[&str], timeout: Duration) -> Option<CommandOutput> {
    if !command_exists(program) && !program.starts_with('/') {
        return None;
    }
    run(program, args, timeout).ok()
}
