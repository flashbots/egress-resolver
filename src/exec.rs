//! Minimal process-execution abstraction so the firewall and conntrack logic
//! can be unit-tested with a fake.

use std::io::{self, Write};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Default)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

pub trait Exec {
    /// Run `program` with `args`, optionally feeding `stdin`, and capture output.
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<Output>;
}

/// Runs real processes.
pub struct SystemExec;

impl Exec for SystemExec {
    fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<Output> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C");
        let mut child = cmd.spawn()?;
        if let Some(input) = stdin {
            let mut pipe = child.stdin.take().expect("stdin piped");
            pipe.write_all(input.as_bytes())?;
            drop(pipe);
        }
        let out = child.wait_with_output()?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Clone, PartialEq)]
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub stdin: Option<String>,
    }

    /// Scripted fake: pops one canned `Output` per call, records every call.
    #[derive(Default)]
    pub struct FakeExec {
        pub calls: Vec<Call>,
        pub responses: VecDeque<Output>,
    }

    impl FakeExec {
        pub fn respond(mut self, status: i32, stdout: &str) -> Self {
            self.responses.push_back(Output {
                status,
                stdout: stdout.to_string(),
                stderr: String::new(),
            });
            self
        }
    }

    impl Exec for FakeExec {
        fn run(&mut self, program: &str, args: &[&str], stdin: Option<&str>) -> io::Result<Output> {
            self.calls.push(Call {
                program: program.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                stdin: stdin.map(|s| s.to_string()),
            });
            Ok(self.responses.pop_front().unwrap_or_default())
        }
    }
}
