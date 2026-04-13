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

use securecrawl::supabase_writer::SupabaseWriter;
use securecrawl::{Finding, ScanOpts, run_scan};

#[derive(Clone)]
struct AppState {
    api_key: Arc<String>,
    writer: SupabaseWriter,
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
    let supabase_url =
        std::env::var("SUPABASE_URL").context("SUPABASE_URL env var is required")?;
    let supabase_key = std::env::var("SUPABASE_SERVICE_ROLE_KEY")
        .context("SUPABASE_SERVICE_ROLE_KEY env var is required")?;

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .context("PORT must be a valid u16")?;

    let writer = SupabaseWriter::new(supabase_url, supabase_key)?;

    let state = AppState {
        api_key: Arc::new(api_key),
        writer,
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
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected = format!("Bearer {}", state.api_key);
    if auth != expected {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }

    let scan_id = body
        .scan_id
        .clone()
        .ok_or((StatusCode::BAD_REQUEST, "scan_id required".into()))?;

    let url = if body.url.starts_with("http://") || body.url.starts_with("https://") {
        body.url.clone()
    } else {
        format!("https://{}", body.url)
    };

    info!(%scan_id, %url, "scheduling scan");

    let opts = ScanOpts {
        url,
        ..ScanOpts::default()
    };

    // Fire-and-forget: spawn the scan as a background task. The HTTP
    // handler returns 202 immediately; findings stream into Supabase
    // as they're discovered, and the scan row is flipped to
    // running → completed / failed as the task progresses.
    let writer = state.writer.clone();
    let bg_scan_id = scan_id.clone();

    tokio::spawn(async move {
        if let Err(e) = writer.update_scan_status(&bg_scan_id, "running").await {
            error!(%bg_scan_id, error = %e, "failed to mark scan as running");
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<Finding>>(100);

        // Drain task: writes each batch of findings into Supabase.
        let drain_writer = writer.clone();
        let drain_scan_id = bg_scan_id.clone();
        let drain = tokio::spawn(async move {
            while let Some(batch) = rx.recv().await {
                if let Err(e) = drain_writer
                    .insert_findings(&drain_scan_id, &batch)
                    .await
                {
                    error!(scan_id = %drain_scan_id, error = %e, "findings insert failed");
                }
            }
        });

        let scan_result = run_scan(opts, Some(tx)).await;
        let _ = drain.await;

        match scan_result {
            Ok(report) => {
                info!(
                    %bg_scan_id,
                    findings = report.findings.len(),
                    "scan complete"
                );
                if let Err(e) = writer.update_scan_status(&bg_scan_id, "completed").await {
                    error!(%bg_scan_id, error = %e, "failed to mark scan as completed");
                }
            }
            Err(e) => {
                error!(%bg_scan_id, error = %e, "scan failed");
                if let Err(update_err) = writer.update_scan_status(&bg_scan_id, "failed").await {
                    error!(
                        %bg_scan_id,
                        error = %update_err,
                        "failed to mark scan as failed"
                    );
                }
            }
        }
    });

    Ok(Json(serde_json::json!({
        "accepted": true,
        "scan_id": scan_id,
    })))
}
