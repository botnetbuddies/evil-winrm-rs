//! One-command capture, stream presentation and transcript output.
use crate::session::{ConsoleEvent, Output, Session};
use anyhow::{Result, bail};
use std::{
    fs::File,
    io::{IsTerminal, Write},
};
use tokio_util::sync::CancellationToken;
pub(super) async fn cancellable(session: &Session, line: &str) -> Result<Output> {
    session.execute(line, CancellationToken::new()).await
}

pub(super) struct CommandSink<'a> {
    pub(super) log: &'a mut Option<File>,
    pub(super) output: Output,
    pub(super) capture: bool,
    pub(super) status: bool,
}
impl CommandSink<'_> {
    fn record(&mut self, output: &Output) {
        if !self.capture && !self.status {
            return;
        }
        self.output.stdout.push_str(&output.stdout);
        self.output.errors.extend(output.errors.iter().cloned());
        self.output.warnings.extend(output.warnings.iter().cloned());
        self.output.verbose.extend(output.verbose.iter().cloned());
        self.output.debug.extend(output.debug.iter().cloned());
        self.output
            .information
            .extend(output.information.iter().cloned());
        self.output.failed |= output.failed;
        if output.exit_code.is_some() {
            self.output.exit_code = output.exit_code;
        }
    }
}

pub(super) async fn command_output(
    session: &Session,
    line: &str,
    raw: bool,
    sink: &CommandSink<'_>,
) -> Result<Output> {
    if sink.status {
        session
            .execute_with_status(line, raw, CancellationToken::new())
            .await
    } else {
        cancellable(session, line).await
    }
}

pub(super) async fn script_output(
    session: &Session,
    script: &str,
    sink: &mut CommandSink<'_>,
) -> Result<()> {
    if sink.status {
        let output = command_output(session, script, true, sink).await?;
        print_output(output, sink, false)
    } else {
        emit(&session.raw(script).await?, sink)
    }
}

pub(super) fn print_output(output: Output, log: &mut CommandSink<'_>, colors: bool) -> Result<()> {
    log.record(&output);
    let failed = output.failed || !output.errors.is_empty();
    if log.capture {
        if let Some(file) = &mut *log.log {
            write!(file, "{}", output.stdout)?;
            for (label, values) in [
                ("Error", &output.errors),
                ("Warning", &output.warnings),
                ("Verbose", &output.verbose),
                ("Debug", &output.debug),
                ("Information", &output.information),
            ] {
                for value in values {
                    writeln!(file, "{label}: {value}")?;
                }
            }
        }
        if failed {
            bail!("remote pipeline failed");
        }
        return Ok(());
    }
    if output.console.is_empty() {
        print!("{}", output.stdout);
    } else {
        for event in output.console {
            match event {
                ConsoleEvent::Text(text) => print!("{text}"),
                ConsoleEvent::ClearScreen if std::io::stdout().is_terminal() => {
                    print!("\x1b[2J\x1b[H")
                }
                ConsoleEvent::ClearScreen => (),
            }
        }
    }
    if let Some(log) = &mut *log.log {
        write!(log, "{}", output.stdout)?;
    }
    for (label, values) in [
        ("Error", output.errors),
        ("Warning", output.warnings),
        ("Verbose", output.verbose),
        ("Debug", output.debug),
        ("Information", output.information),
    ] {
        for value in values {
            if colors {
                eprintln!(
                    "\x1b[{}m{label}: {value}\x1b[0m",
                    if label == "Error" { 31 } else { 33 }
                );
            } else {
                eprintln!("{label}: {value}");
            }
            if let Some(log) = &mut *log.log {
                writeln!(log, "{label}: {value}")?;
            }
        }
    }
    if failed {
        bail!("remote pipeline failed");
    }
    Ok(())
}

pub(super) fn emit(text: &str, log: &mut CommandSink<'_>) -> Result<()> {
    if log.capture || log.status {
        log.output.stdout.push_str(text);
    }
    if !log.capture {
        print!("{text}");
    }
    if let Some(log) = &mut *log.log {
        write!(log, "{text}")?;
    }
    Ok(())
}
