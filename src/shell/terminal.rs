//! Terminal lifecycle, history, signal handling and the interactive prompt loop.
use super::{
    completion::ShellHelper,
    dispatch::{execute_line, execute_line_to},
    output::CommandSink,
};
use crate::{
    cli::Cli,
    output::{CommandReport, RunResult},
    session::{Output, Session},
};
use anyhow::{Context, Result};
use md5::Digest;
use rustyline::{Config, Editor, error::ReadlineError, history::DefaultHistory};
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{IsTerminal, Write},
    path::PathBuf,
};
fn state_path(name: &str) -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("evil-winrm-rs")
        .join(name)
}

pub fn run(runtime: &tokio::runtime::Runtime, session: Session, args: &Cli) -> Result<RunResult> {
    let signal_session = session.clone();
    let signal_task = runtime.spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            signal_session.cancel_current();
        }
    });
    struct SignalGuard(tokio::task::JoinHandle<()>);
    impl Drop for SignalGuard {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _signal_guard = SignalGuard(signal_task);
    let mut log = if args.log || args.log_file.is_some() {
        let path = args
            .log_file
            .clone()
            .unwrap_or_else(|| state_path(&format!("session-{}.log", uuid::Uuid::new_v4())));
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Some(
            options
                .open(&path)
                .with_context(|| format!("opening log {}", path.display()))?,
        )
    } else {
        None
    };
    if let Some(command) = &args.command {
        let mut sink = CommandSink {
            log: &mut log,
            output: Output::default(),
            capture: args.json,
            status: true,
        };
        let error = runtime
            .block_on(execute_line_to(&session, command, args, &mut sink))
            .err()
            .map(|error| format!("{error:#}"));
        let report = CommandReport::new(sink.output, error);
        return Ok(RunResult {
            code: report.process_code(args.exit_code),
            report: Some(report),
        });
    }
    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(rustyline::CompletionType::List)
        .build();
    let mut editor = Editor::<ShellHelper, DefaultHistory>::with_config(config)?;
    editor.set_helper(Some(ShellHelper {
        session: session.clone(),
        runtime: runtime.handle().clone(),
        remote_paths: !args.no_rpath_completion,
        scripts: args.scripts.clone(),
        executables: args.executables.clone(),
        cwd: String::new(),
        remote_cache: RefCell::new(HashMap::new()),
    }));
    editor.bind_sequence(
        rustyline::KeyEvent(rustyline::KeyCode::Delete, rustyline::Modifiers::CTRL),
        rustyline::Cmd::Kill(rustyline::Movement::ForwardWord(
            1,
            rustyline::At::AfterEnd,
            rustyline::Word::Emacs,
        )),
    );
    let identity = format!(
        "{}@{}",
        args.user.as_deref().unwrap_or("ticket"),
        args.host.as_deref().unwrap_or("host")
    );
    let history = state_path(&format!(
        "history-{}",
        hex::encode(md5::Md5::digest(identity.as_bytes()))
    ));
    if let Some(parent) = history.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = editor.load_history(&history);
    let mut cwd = String::from("?");
    loop {
        if !session.jea {
            {
                let path = runtime.block_on(session.raw("$pwd.Path"))?;
                cwd = path.trim().into()
            }
        }
        let label = if session.jea { "JEA" } else { &cwd };
        let prompt = if args.no_colors || !std::io::stdout().is_terminal() {
            format!("*evil-winrm-rs* PS {label}> ")
        } else {
            format!("\x1b[31m*evil-winrm-rs*\x1b[0m \x1b[33mPS\x1b[0m {label}> ")
        };
        editor.helper_mut().unwrap().cwd.clone_from(&cwd);
        match editor.readline(&prompt) {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                editor.add_history_entry(&line)?;
                // append_history uses the history file lock to preserve concurrent sessions.
                if !history.exists() {
                    File::create(&history)?;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o600))?;
                }
                editor.append_history(&history)?;
                editor
                    .helper_mut()
                    .unwrap()
                    .remote_cache
                    .borrow_mut()
                    .clear();
                match runtime.block_on(execute_line(&session, &line, args, &mut log)) {
                    Ok(false) => break,
                    Ok(true) => (),
                    Err(e) => {
                        eprintln!("Error: {e:#}");
                        if let Some(log) = &mut log {
                            writeln!(log, "Error: {e:#}")?;
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(RunResult {
        code: 0,
        report: None,
    })
}
