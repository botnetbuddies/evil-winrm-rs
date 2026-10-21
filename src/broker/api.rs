//! Local HTTP control adapter; all ownership and execution stay in Broker.
use super::{
    Broker,
    models::{Cancel, ExecutionReply, ExecutionRequest, Login, SessionId, SocksStart, SocksStop},
    stream::Frames,
};
use anyhow::Context;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":format!("{:#}",self.0)})),
        )
            .into_response()
    }
}
type Reply<T> = std::result::Result<Json<T>, ApiError>;
pub(super) fn router(broker: Broker) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .route("/sessions", get(list))
        .route("/login", post(login))
        .route("/attach", post(attach))
        .route("/execute", post(execute))
        .route("/cancel", post(cancel))
        .route("/logout", post(logout))
        .route("/shutdown", post(shutdown))
        .route("/socks", get(socks_list).post(socks_start))
        .route("/socks/stop", post(socks_stop))
        .layer(DefaultBodyLimit::max(32 * 1024 * 1024))
        .with_state(broker)
}
async fn list(State(b): State<Broker>) -> Json<Vec<super::models::SessionInfo>> {
    Json(b.list().await)
}
async fn login(
    State(b): State<Broker>,
    Json(args): Json<Login>,
) -> Reply<super::models::SessionInfo> {
    Ok(Json(b.login(args).await?))
}
async fn attach(
    State(b): State<Broker>,
    Json(args): Json<SessionId>,
) -> Reply<super::models::AttachInfo> {
    Ok(Json(b.attach(args.session_id).await?))
}
async fn cancel(State(b): State<Broker>, Json(args): Json<Cancel>) -> Reply<serde_json::Value> {
    b.cancel(args).await?;
    Ok(Json(serde_json::json!({"cancelled":true})))
}
async fn logout(State(b): State<Broker>, Json(args): Json<SessionId>) -> Reply<serde_json::Value> {
    let id = b.logout(args.session_id).await?;
    Ok(Json(serde_json::json!({"closed":id})))
}
async fn shutdown(State(b): State<Broker>) -> Json<serde_json::Value> {
    b.shutdown.cancel();
    Json(serde_json::json!({"shutdown":true}))
}
async fn socks_list(State(b): State<Broker>) -> Json<Vec<crate::socks::ListenerInfo>> {
    Json(b.list_socks().await)
}
async fn socks_start(
    State(b): State<Broker>,
    Json(args): Json<SocksStart>,
) -> Reply<crate::socks::ListenerInfo> {
    Ok(Json(b.start_socks(args).await?))
}
async fn socks_stop(
    State(b): State<Broker>,
    Json(args): Json<SocksStop>,
) -> Reply<serde_json::Value> {
    b.stop_socks(args).await?;
    Ok(Json(serde_json::json!({"stopped":true})))
}
async fn execute(State(broker): State<Broker>, request: Request) -> Reply<ExecutionReply> {
    if request
        .headers()
        .get("content-type")
        .is_some_and(|h| h == "application/x-ewr-pipeline")
    {
        let mut reader = Frames::new(request.into_body());
        let args: ExecutionRequest = serde_json::from_slice(
            &reader
                .next(32 * 1024 * 1024)
                .await?
                .context("missing request metadata")?,
        )?;
        let cancellation = Cancel {
            session_id: args.session_id,
            request_id: args.request_id.clone(),
        };
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let execute = broker.execute(args, Some(rx));
        tokio::pin!(execute);
        let feed = async move {
            while let Some(bytes) = reader.next(2 * 1024 * 1024).await? {
                let text = std::str::from_utf8(&bytes)?;
                for value in psrp_rs::clixml::parse_clixml(text)? {
                    if tx.send(value).await.is_err() {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            }
            Ok(())
        };
        tokio::pin!(feed);
        let response = tokio::select! {
            result = &mut execute => result,
            input = &mut feed => {
                if let Err(error) = input {
                    let _ = broker.cancel(cancellation).await;
                    let _ = execute.await;
                    return Err(ApiError(error));
                }
                execute.await
            },
        }?;
        Ok(Json(response))
    } else {
        let Json(args) = Json::<ExecutionRequest>::from_request(request, &())
            .await
            .map_err(|e| anyhow::anyhow!("invalid execute request: {e}"))?;
        Ok(Json(broker.execute(args, None).await?))
    }
}
