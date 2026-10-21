//! Authenticated local control client; command input is streamed, never buffered whole.
use super::{
    models::{Cancel, ExecutionReply, ExecutionRequest},
    state,
    stream::frame,
};
use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use std::{path::Path, time::Duration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    state: state::State,
}
impl Client {
    pub fn from_file(path: Option<&Path>) -> Result<Self> {
        let state = state::read(&state::path(path))?;
        Ok(Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .connect_timeout(Duration::from_secs(5))
                .build()?,
            state,
        })
    }
    pub(crate) fn request(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .post(format!("http://{}{path}", self.state.address))
            .bearer_auth(&self.state.token)
    }
    pub async fn post<B: Serialize, R: DeserializeOwned>(&self, path: &str, body: &B) -> Result<R> {
        decode(self.request(path).json(body).send().await?).await
    }
    pub async fn get<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        decode(
            self.http
                .get(format!("http://{}{path}", self.state.address))
                .bearer_auth(&self.state.token)
                .send()
                .await?,
        )
        .await
    }
    pub(crate) async fn execute(
        &self,
        args: ExecutionRequest,
        input: Option<mpsc::Receiver<psrp_rs::PsValue>>,
        cancel: CancellationToken,
    ) -> Result<ExecutionReply> {
        if cancel.is_cancelled() {
            bail!("operation cancelled");
        }
        let cancellation = Cancel {
            session_id: args.session_id,
            request_id: args.request_id.clone(),
        };
        let request = if let Some(input) = input {
            use tokio_stream::{StreamExt, wrappers::ReceiverStream};
            let metadata = frame(&serde_json::to_vec(&args)?);
            let stream = tokio_stream::once(Ok::<_, std::io::Error>(metadata)).chain(
                ReceiverStream::new(input)
                    .map(|value| Ok(frame(psrp_rs::clixml::to_clixml(&value).as_bytes()))),
            );
            self.request("/execute")
                .header("content-type", "application/x-ewr-pipeline")
                .body(reqwest::Body::wrap_stream(stream))
        } else {
            self.request("/execute").json(&args)
        };
        let send = request.send();
        tokio::pin!(send);
        let response = tokio::select! {
            result=&mut send=>result?,
            _=cancel.cancelled()=>{
                let _=self.request("/cancel").timeout(Duration::from_secs(3)).json(&cancellation).send().await;
                tokio::time::timeout(Duration::from_secs(15),&mut send).await.context("broker cancellation acknowledgement timed out")??
            }
        };
        decode(response).await
    }
}
async fn decode<R: DeserializeOwned>(response: reqwest::Response) -> Result<R> {
    let status = response.status();
    if !status.is_success() {
        let text: serde_json::Value = response.json().await.unwrap_or_default();
        bail!(
            "broker request failed (HTTP {status}): {}",
            text["error"].as_str().unwrap_or("request rejected")
        );
    }
    Ok(response.json().await?)
}
