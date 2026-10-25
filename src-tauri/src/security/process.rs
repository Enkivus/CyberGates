use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

use wait_timeout::ChildExt;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::error::{AppError, AppResult};

const MAX_CAPTURE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn combined(&self) -> String {
        let mut out = self.stdout.trim().to_string();
        if out.is_empty() {
            out = self.stderr.trim().to_string();
        }
        out
    }
}

/// Execute a program directly (never through a shell) with a hard timeout and
/// bounded output capture. Arguments are passed as an array, not concatenated.
pub fn run_with_limit(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_capture: usize,
) -> AppResult<CommandOutput> {
    if !Path::new(program).is_absolute() {
        return Err(AppError::Validation(
            "program path must be absolute".to_string(),
        ));
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command
        .spawn()
        .map_err(|err| AppError::Internal(format!("could not start {program}: {err}")))?;

    // Drain both pipes concurrently while the child runs. Waiting first can
    // deadlock any program whose output exceeds the OS pipe buffer.
    let stdout_reader = spawn_reader(child.stdout.take(), max_capture);
    let stderr_reader = spawn_reader(child.stderr.take(), max_capture);

    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            kill_child_tree(&mut child);
            let _ = child.wait();
            None
        }
        Err(err) => {
            kill_child_tree(&mut child);
            let _ = child.wait();
            let _ = join_reader(stdout_reader);
            let _ = join_reader(stderr_reader);
            return Err(AppError::Internal(format!(
                "failed while waiting for {program}: {err}"
            )));
        }
    };

    let stdout = join_reader(stdout_reader);
    let stderr = join_reader(stderr_reader);

    Ok(CommandOutput {
        success: status.map(|s| s.success()).unwrap_or(false),
        stdout,
        stderr,
    })
}

fn kill_child_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let process_group = -(child.id() as i32);
        // The child is placed in a dedicated process group immediately before
        // spawn. Killing the group also closes pipes inherited by descendants.
        let _ = unsafe { libc::kill(process_group, libc::SIGKILL) };
    }
    let _ = child.kill();
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: Option<R>,
    max_capture: usize,
) -> Option<JoinHandle<String>> {
    let mut reader = reader?;
    Some(std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let remaining = max_capture.saturating_sub(kept.len());
                    if remaining > 0 {
                        kept.extend_from_slice(&buffer[..read.min(remaining)]);
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&kept).to_string()
    }))
}

fn join_reader(handle: Option<JoinHandle<String>>) -> String {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}

pub fn run_optional(program: &str, args: &[&str], timeout: Duration) -> Option<CommandOutput> {
    run_optional_with_limit(program, args, timeout, MAX_CAPTURE_BYTES as usize)
}

pub fn run_optional_with_limit(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_capture: usize,
) -> Option<CommandOutput> {
    if !Path::new(program).is_absolute() {
        return None;
    }
    run_with_limit(program, args, timeout, max_capture).ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn drains_output_larger_than_pipe_buffer() {
        let output = run_with_limit(
            "/usr/bin/head",
            &["-c", "200000", "/dev/zero"],
            Duration::from_secs(5),
            MAX_CAPTURE_BYTES as usize,
        )
        .expect("head should run");
        assert!(output.success);
        assert_eq!(output.stdout.len(), 200_000);
    }

    #[test]
    fn truncates_capture_but_does_not_deadlock() {
        let output = run_with_limit(
            "/usr/bin/head",
            &["-c", "700000", "/dev/zero"],
            Duration::from_secs(5),
            MAX_CAPTURE_BYTES as usize,
        )
        .expect("head should run");
        assert!(output.success);
        assert_eq!(output.stdout.len(), MAX_CAPTURE_BYTES as usize);
    }

    #[test]
    fn rejects_program_lookup_through_path() {
        assert!(run_with_limit("head", &[], Duration::from_millis(1), 16).is_err());
        assert!(run_optional("head", &[], Duration::from_millis(1)).is_none());
    }

    #[test]
    fn timeout_kills_descendants_that_inherit_output_pipes() {
        let started = std::time::Instant::now();
        let output = run_with_limit(
            "/bin/sh",
            &["-c", "/bin/sleep 30 & wait"],
            Duration::from_millis(100),
            128,
        )
        .expect("timeout should return a process result");
        assert!(!output.success);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
