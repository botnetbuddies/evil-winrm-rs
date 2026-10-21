//! Execute and cancel requests without allowing a queued client to cancel another client.
use super::{
    Broker,
    models::{AttachInfo, Cancel, ExecutionReply, ExecutionRequest},
};
use anyhow::{Result, bail};
use psrp_rs::PsValue;
use tokio::sync::mpsc;
impl Broker {
    pub async fn attach(&self, id: Option<u64>) -> Result<AttachInfo> {
        let (_, entry) = self.resolve(id).await?;
        Ok(AttachInfo {
            info: entry.info,
            initial_functions: entry.session.function_baseline(),
        })
    }
    pub async fn execute(
        &self,
        args: ExecutionRequest,
        input: Option<mpsc::Receiver<PsValue>>,
    ) -> Result<ExecutionReply> {
        let (id, entry) = self.resolve(args.session_id).await?;
        if args.raw && entry.session.jea {
            bail!("script helpers are unavailable on a JEA endpoint");
        }
        let token = self.shutdown.child_token();
        let key = (id, args.request_id.clone());
        {
            let mut jobs = self.jobs.lock().await;
            if jobs.contains_key(&key) {
                bail!("duplicate request id");
            }
            jobs.insert(key.clone(), token.clone());
        }
        let result = async {
            let _lease = tokio::select! {
                _ = token.cancelled() => bail!("operation cancelled"),
                lease = entry.lease.lock() => lease,
            };
            entry
                .session
                .execute_request(&args.text, args.raw, input, args.status, token.clone())
                .await
        }
        .await;
        self.jobs.lock().await.remove(&key);
        Ok(match result {
            Ok(mut output) => {
                let console = std::mem::take(&mut output.console);
                ExecutionReply {
                    output: Some(output),
                    console,
                    error: None,
                    open: entry.session.is_open(),
                }
            }
            Err(error) => ExecutionReply {
                output: None,
                console: Vec::new(),
                error: Some(format!("{error:#}")),
                open: entry.session.is_open(),
            },
        })
    }
    pub async fn cancel(&self, args: Cancel) -> Result<()> {
        let (id, _) = self.resolve(args.session_id).await?;
        if let Some(token) = self.jobs.lock().await.get(&(id, args.request_id)) {
            token.cancel();
        }
        Ok(())
    }
}
