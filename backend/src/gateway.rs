use std::{io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{extract::Extension, routing::get, Router};
use axum_server::{tls_rustls::RustlsConfig, Handle as TlsHandle};
use serde::Serialize;
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex},
};
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir};
use tracing::error;

use crate::{handle_request, nginx_bridge, AppState, RequestScheme};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GatewayStatus {
    pub(crate) running: bool,
    pub(crate) http_listen: String,
    pub(crate) https_listen: Option<String>,
}

struct Runtime {
    running: bool,
    http_shutdown: Option<oneshot::Sender<()>>,
    tls_handle: Option<TlsHandle>,
    http_address: Option<String>,
    https_address: Option<String>,
}

pub(crate) struct GatewayController {
    runtime: Mutex<Runtime>,
    state: Arc<AppState>,
    http_listen: String,
    https_listen: Option<String>,
    tls_config: Option<RustlsConfig>,
    body_limit: usize,
}

impl GatewayController {
    pub(crate) fn new(
        state: Arc<AppState>,
        http_listen: String,
        https_listen: Option<String>,
        tls_config: Option<RustlsConfig>,
        body_limit: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime: Mutex::new(Runtime {
                running: false,
                http_shutdown: None,
                tls_handle: None,
                http_address: None,
                https_address: None,
            }),
            state,
            http_listen,
            https_listen,
            tls_config,
            body_limit,
        })
    }

    pub(crate) async fn status(&self) -> GatewayStatus {
        let runtime = self.runtime.lock().await;
        GatewayStatus {
            running: runtime.running,
            http_listen: runtime
                .http_address
                .clone()
                .unwrap_or_else(|| self.http_listen.clone()),
            https_listen: runtime
                .https_address
                .clone()
                .or_else(|| self.https_listen.clone()),
        }
    }

    pub(crate) async fn start(&self) -> Result<GatewayStatus> {
        let mut runtime = self.runtime.lock().await;
        if runtime.running {
            return Ok(GatewayStatus {
                running: true,
                http_listen: runtime
                    .http_address
                    .clone()
                    .unwrap_or_else(|| self.http_listen.clone()),
                https_listen: runtime
                    .https_address
                    .clone()
                    .or_else(|| self.https_listen.clone()),
            });
        }

        let configured: SocketAddr = self
            .http_listen
            .parse()
            .with_context(|| format!("invalid gateway listener address: {}", self.http_listen))?;
        let listener = TcpListener::bind(configured).await.map_err(|error| {
            let hint = match error.kind() {
                ErrorKind::AddrInUse => {
                    "address is already in use; stop the conflicting service or change server.listen"
                }
                ErrorKind::PermissionDenied => {
                    "permission denied; choose an allowed listener address or run with the required permission"
                }
                _ => "check the listener address and operating-system error",
            };
            anyhow::Error::new(error)
                .context(format!("failed to bind gateway listener {configured}; {hint}"))
        })?;
        let http_address = listener.local_addr()?;
        let app = public_app(self.state.clone(), self.body_limit, "http");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            if let Err(error) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            {
                error!(error = %error, "gateway HTTP server failed");
            }
        });

        let (tls_handle, https_address) = match (&self.tls_config, &self.https_listen) {
            (Some(tls_config), Some(tls_listen)) => {
                let tls_addr: SocketAddr = tls_listen
                    .parse()
                    .with_context(|| format!("invalid tls.listen: {tls_listen}"))?;
                let tls_app = public_app(self.state.clone(), self.body_limit, "https");
                let handle = TlsHandle::new();
                let task_handle = handle.clone();
                let tls_config = tls_config.clone();
                tokio::spawn(async move {
                    if let Err(error) = axum_server::bind_rustls(tls_addr, tls_config)
                        .handle(task_handle)
                        .serve(tls_app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                    {
                        error!(error = %error, "gateway TLS server failed");
                    }
                });
                (Some(handle), Some(tls_addr.to_string()))
            }
            _ => (None, None),
        };

        runtime.running = true;
        runtime.http_shutdown = Some(shutdown_tx);
        runtime.tls_handle = tls_handle;
        runtime.http_address = Some(http_address.to_string());
        runtime.https_address = https_address;
        Ok(GatewayStatus {
            running: true,
            http_listen: http_address.to_string(),
            https_listen: runtime.https_address.clone(),
        })
    }

    pub(crate) async fn stop(&self) -> GatewayStatus {
        let mut runtime = self.runtime.lock().await;
        if let Some(shutdown) = runtime.http_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(handle) = runtime.tls_handle.take() {
            handle.graceful_shutdown(Some(Duration::from_secs(30)));
        }
        runtime.running = false;
        runtime.http_address = None;
        runtime.https_address = None;
        GatewayStatus {
            running: false,
            http_listen: self.http_listen.clone(),
            https_listen: self.https_listen.clone(),
        }
    }
}

fn public_app(state: Arc<AppState>, body_limit: usize, scheme: &'static str) -> Router {
    Router::new()
        .route(
            "/_bot_gate/check",
            get(nginx_bridge::check).post(nginx_bridge::check),
        )
        .route(
            "/_bot_gate/challenge",
            get(nginx_bridge::challenge).post(nginx_bridge::challenge),
        )
        .route(
            "/_bot_gate/deny",
            get(nginx_bridge::deny_page).post(nginx_bridge::deny_page),
        )
        .nest_service(
            "/_bot_gate/assets",
            ServeDir::new(state.frontend_dist.join("assets")),
        )
        .fallback(handle_request)
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(Extension(RequestScheme(scheme)))
        .with_state(state)
}
