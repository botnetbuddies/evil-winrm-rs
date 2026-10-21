//! Public session API. A worker owns the runspace and serializes its requests.
mod execution;
mod host;
mod limits;
mod open;
mod output;
#[cfg(feature = "mcp")]
mod remote;
mod stop;
mod transport;
mod worker;
use anyhow::{Context, Result, bail};
pub use output::{ConsoleEvent, Output, render};
use psrp_rs::PsValue;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
enum Request {
    Execute {
        text: String,
        raw: bool,
        status: bool,
        input: Option<mpsc::Receiver<PsValue>>,
        cancel: CancellationToken,
        reply: oneshot::Sender<Result<Output>>,
    },
    Close(oneshot::Sender<Result<()>>),
}

#[derive(Clone)]
pub struct Session {
    tx: mpsc::Sender<Request>,
    pub jea: bool,
    active: Arc<Mutex<Option<CancellationToken>>>,
    alive: Arc<AtomicBool>,
    initial_functions: Arc<Vec<String>>,
}

impl Session {
    #[cfg(feature = "mcp")]
    pub(crate) fn function_baseline(&self) -> Vec<String> {
        self.initial_functions.as_ref().clone()
    }
    #[cfg(feature = "mcp")]
    pub(crate) async fn execute_request(
        &self,
        text: &str,
        raw: bool,
        input: Option<mpsc::Receiver<PsValue>>,
        status: bool,
        cancel: CancellationToken,
    ) -> Result<Output> {
        self.request_full(text, raw, input, status, cancel).await
    }
    pub fn is_open(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub fn cancel_current(&self) {
        tracing::debug!("interrupt requested");
        if let Some(token) = self.active.lock().unwrap().as_ref() {
            token.cancel();
        }
    }

    pub async fn execute(&self, text: &str, cancel: CancellationToken) -> Result<Output> {
        self.request(text, false, cancel).await
    }
    /// Execute one command and collect native/script numeric status without stale state.
    pub async fn execute_with_status(
        &self,
        text: &str,
        raw: bool,
        cancel: CancellationToken,
    ) -> Result<Output> {
        self.request_full(text, raw, None, true, cancel).await
    }
    pub async fn raw(&self, script: &str) -> Result<String> {
        self.raw_cancellable(script, CancellationToken::new()).await
    }
    pub async fn raw_cancellable(&self, script: &str, cancel: CancellationToken) -> Result<String> {
        if self.jea {
            bail!("script helpers are unavailable on a JEA endpoint");
        }
        self.request(script, true, cancel).await?.checked()
    }
    /// Stream bounded input objects through one persistent remote pipeline.
    pub async fn raw_with_input(
        &self,
        script: &str,
        input: mpsc::Receiver<PsValue>,
    ) -> Result<String> {
        if self.jea {
            bail!("script helpers are unavailable on a JEA endpoint");
        }
        self.request_with_input(script, true, Some(input), CancellationToken::new())
            .await?
            .checked()
    }
    /// Functions added after connecting, excluding the endpoint's startup functions.
    pub async fn loaded_functions(&self) -> Result<Vec<String>> {
        let result = self
            .raw("Get-ChildItem Function: | Select-Object -ExpandProperty Name")
            .await?;
        let mut names = result
            .lines()
            .filter(|name| !self.initial_functions.contains(&name.to_ascii_lowercase()))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        names.sort_by_key(|name| name.to_ascii_lowercase());
        names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        Ok(names)
    }
    /// Parse without executing the supplied input, using the endpoint's grammar.
    pub async fn input_is_incomplete(&self, input: &str) -> Result<bool> {
        if self.jea {
            return match crate::command::tokenize(input, true) {
                Ok(tokens) => Ok(matches!(tokens.last(), Some(crate::command::Token::Pipe))),
                Err(error) => Ok(matches!(
                    error.to_string().as_str(),
                    "unclosed quote" | "incomplete escape"
                )),
            };
        }
        let result = self.raw(&format!(
            "& {{ param($source) $tokens=$null; $errors=$null; [void][Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors); (@($errors | Where-Object {{ $_.IncompleteInput }}).Count -gt 0) }} {}",
            crate::command::quote(input)
        )).await?;
        match result.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => bail!("unexpected PowerShell parser response"),
        }
    }
    async fn request(&self, text: &str, raw: bool, cancel: CancellationToken) -> Result<Output> {
        self.request_with_input(text, raw, None, cancel).await
    }
    async fn request_with_input(
        &self,
        text: &str,
        raw: bool,
        input: Option<mpsc::Receiver<PsValue>>,
        cancel: CancellationToken,
    ) -> Result<Output> {
        self.request_full(text, raw, input, false, cancel).await
    }
    async fn request_full(
        &self,
        text: &str,
        raw: bool,
        input: Option<mpsc::Receiver<PsValue>>,
        status: bool,
        cancel: CancellationToken,
    ) -> Result<Output> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Request::Execute {
                text: text.into(),
                raw,
                status,
                input,
                cancel,
                reply,
            })
            .await
            .context("session is closed")?;
        rx.await
            .context("session stopped before returning output")?
    }
    pub async fn close(&self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Request::Close(reply))
            .await
            .context("session is closed")?;
        rx.await.context("session stopped while closing")?
    }
}
