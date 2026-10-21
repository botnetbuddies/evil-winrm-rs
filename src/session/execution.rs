//! Execute one request, including input streaming, ordered host output and status.
use super::{ConsoleEvent, Output, host::HostBuffer, transport::Transport};
use crate::command::{interactive_pipeline, jea_pipelines};
use anyhow::Result;
use psrp_rs::{Pipeline, PsValue, PsrpError, RunspacePool};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
pub(super) struct Execution {
    pub text: String,
    pub raw: bool,
    pub status: bool,
    pub input: Option<mpsc::Receiver<PsValue>>,
    pub cancel: CancellationToken,
}
pub(super) async fn run(
    pool: &mut RunspacePool<Transport>,
    host_buffer: &HostBuffer,
    jea: bool,
    command: Execution,
) -> Result<Output> {
    let Execution {
        text,
        raw,
        status,
        mut input,
        cancel,
    } = command;

    if status && !jea {
        Pipeline::new("$global:LASTEXITCODE = $null")
            .retaining_failed_output()
            .run_all_streams(pool)
            .await?;
        host_buffer.0.lock().unwrap().clear();
    }
    let pipelines = if raw {
        vec![Pipeline::new(text)]
    } else if jea {
        jea_pipelines(&text)?
    } else {
        vec![interactive_pipeline(&text)]
    };
    let mut output = Output::default();
    for pipeline in pipelines {
        let mut result = if let Some(mut input) = input.take() {
            let mut handle = pipeline
                .with_input(true)
                .retaining_failed_output()
                .start(pool)
                .await?;
            loop {
                let value = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    value = input.recv() => value,
                };
                let Some(value) = value else {
                    break;
                };
                handle.write_input(value).await?;
            }
            handle.collect_with_cancel(cancel.clone()).await?
        } else {
            pipeline
                .retaining_failed_output()
                .run_all_streams_with_cancel(pool, cancel.clone())
                .await?
        };
        // A pipeline can finish while Ctrl+C is in flight. Preserve the
        // cancellation so a transfer does not start its next chunk or report
        // the producer's closed input channel instead of the interruption.
        if cancel.is_cancelled() {
            return Err(PsrpError::Cancelled.into());
        }
        // The host already captured output in callback order.
        result.output.clear();
        output.append(result);
        if output.failed {
            break;
        }
    }
    output.console = host_buffer.0.lock().unwrap().drain(..).collect();
    output.stdout = output
        .console
        .iter()
        .filter_map(|event| match event {
            ConsoleEvent::Text(text) => Some(text.as_str()),
            ConsoleEvent::ClearScreen => None,
        })
        .collect();
    if status {
        output.exit_code = *host_buffer.1.lock().unwrap();
        if output.exit_code.is_none() && !jea && !output.failed && !cancel.is_cancelled() {
            let code = Pipeline::new("$global:LASTEXITCODE")
                .retaining_failed_output()
                .run_all_streams_with_cancel(pool, cancel.clone())
                .await?;
            output.exit_code = code.output.first().and_then(PsValue::as_i32);
        }
    }
    Ok(output)
}
