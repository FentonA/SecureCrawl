use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use securecrawl::{ScanOpts, ScanReport, run_scan};

#[derive(Clone)]
struct AppState {
    api_key: Arc<String>,
}

#[derive(Deserialize)]
struct ScanRequest {
    url: String,
    #[serde(default, alias = "scanId")]
    scan_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info,axum=info".into()),
        )
        .init();

    let api_key = std::env::var("API_KEY").context("API_KEY env var is required")?;
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .context("PORT must be a valid u16")?;

    let state = AppState {
        api_key: Arc::new(api_key),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScanRequest>,
) -> Result<Json<ScanReport>, (StatusCode, String)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected = format!("Bearer {}", state.api_key);
    if auth != expected {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }

    let url = if body.url.starts_with("http://") || body.url.starts_with("https://") {
        body.url.clone()
    } else {
        format!("https://{}", body.url)
    };

    info!(scan_id = ?body.scan_id, url = %url, "starting scan");

    let opts = ScanOpts {
        url,
        ..ScanOpts::default()
    };

    match run_scan(opts).await {
        Ok(report) => {
            info!(
                scan_id = ?body.scan_id,
                findings = report.findings.len(),
                "scan complete"
            );
            Ok(Json(report))
        }
        Err(e) => {
            error!(scan_id = ?body.scan_id, error = %e, "scan failed");
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))
        }
    }
}
