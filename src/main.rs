use anyhow::{Context, Result};
use evil_winrm_rs::{
    cli,
    output::{CommandReport, RunResult},
    shell,
};

fn main() {
    let mut args = cli::parse();
    let outcome = run(&mut args);
    let code = match outcome {
        Ok(outcome) => {
            if let Some(report) = outcome.report {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("serializing result")
                    );
                } else if let Some(error) = report.error {
                    eprintln!("Error: {error}");
                }
            }
            outcome.code
        }
        Err(error) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string(&CommandReport::failure(&error))
                        .expect("serializing error")
                );
            } else {
                eprintln!("Error: {error:#}");
            }
            1
        }
    };
    std::process::exit(code);
}
fn run(args: &mut cli::Cli) -> Result<RunResult> {
    #[cfg(unix)]
    if args.control.daemon_child {
        nix::unistd::setsid().context("detaching broker session")?;
    }
    tracing_subscriber::fmt()
        .with_env_filter(if args.debug {
            "evil_winrm_rs=debug,winrm_rs=debug,psrp_rs=debug"
        } else {
            "error"
        })
        .with_ansi(!args.no_colors && !args.json)
        .with_writer(std::io::stderr)
        .init();
    let runtime = tokio::runtime::Runtime::new()?;
    if args.control.daemon || args.control.broker {
        #[cfg(feature = "mcp")]
        {
            if args.control.broker {
                return evil_winrm_rs::broker::cli::run(&runtime, args);
            }
            if args.control.detach {
                evil_winrm_rs::broker::daemon::detach(args)?;
                evil_winrm_rs::broker::cli::login_after_detach(&runtime, args)?;
            } else {
                runtime.block_on(evil_winrm_rs::broker::daemon::serve(args))?;
            }
            return Ok(RunResult {
                code: 0,
                report: None,
            });
        }
        #[cfg(not(feature = "mcp"))]
        {
            anyhow::bail!("broker support requires the mcp build feature");
        }
    }
    if args.mcp {
        #[cfg(feature = "mcp")]
        {
            runtime.block_on(evil_winrm_rs::mcp::serve(
                args.mcp_host.clone(),
                args.mcp_port,
            ))?;
            return Ok(RunResult {
                code: 0,
                report: None,
            });
        }
        #[cfg(not(feature = "mcp"))]
        {
            anyhow::bail!("rebuild with the mcp feature enabled");
        }
    }
    let profile = evil_winrm_rs::cli::connect_profile(args)?;
    let session = runtime
        .block_on(profile.connect())
        .context("establishing PowerShell runspace")?;
    let result = if let Some(bind) = args.control.socks {
        runtime
            .block_on(evil_winrm_rs::socks::serve(
                profile,
                bind,
                args.control.socks_max_connections as usize,
            ))
            .map(|()| RunResult {
                code: 0,
                report: None,
            })
    } else {
        shell::run(&runtime, session.clone(), args)
    };
    let closed = runtime.block_on(session.close());
    let mut outcome = result?;
    if let Err(error) = closed {
        if let Some(report) = &mut outcome.report {
            report.success = false;
            if report.exit_code == 0 {
                report.exit_code = 1;
            }
            report.error = Some(match report.error.take() {
                Some(previous) => format!("{previous}; closing remote shell: {error:#}"),
                None => format!("closing remote shell: {error:#}"),
            });
            outcome.code = report.process_code(args.exit_code);
        } else {
            return Err(error.context("closing remote shell"));
        }
    }
    Ok(outcome)
}
