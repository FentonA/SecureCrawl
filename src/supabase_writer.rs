use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

use crate::scanner::findings::Finding;

/// Minimal Supabase PostgREST client for streaming findings and updating
/// scan status from the Rust API binary.
#[derive(Clone)]
pub struct SupabaseWriter {
    client: Client,
    url: String,
    service_key: String,
}

impl SupabaseWriter {
    pub fn new(url: String, service_key: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build Supabase HTTP client")?;
        Ok(Self {
            client,
            url,
            service_key,
        })
    }

    /// Bulk-insert a batch of findings into `public.findings`.
    pub async fn insert_findings(&self, scan_id: &str, findings: &[Finding]) -> Result<()> {
        if findings.is_empty() {
            return Ok(());
        }

        let rows: Vec<Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "scan_id": scan_id,
                    "severity": f.severity,
                    "type": f.finding_type,
                    "title": f.title,
                    "description": f.description,
                    "location": f.url,
                    "raw_data": f,
                })
            })
            .collect();

        let resp = self
            .client
            .post(format!("{}/rest/v1/findings", self.url))
            .header("apikey", &self.service_key)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("Content-Type", "application/json")
            .header("Prefer", "return=minimal")
            .json(&rows)
            .send()
            .await
            .context("insert findings request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("insert findings failed: {status} {body}");
        }
        Ok(())
    }

    /// Update a scan row's status (and completed_at on terminal states).
    pub async fn update_scan_status(&self, scan_id: &str, status: &str) -> Result<()> {
        let completed_at = match status {
            "completed" | "failed" => Value::String(chrono::Utc::now().to_rfc3339()),
            _ => Value::Null,
        };

        let body = json!({
            "status": status,
            "completed_at": completed_at,
        });

        let resp = self
            .client
            .patch(format!(
                "{}/rest/v1/scans?id=eq.{}",
                self.url, scan_id
            ))
            .header("apikey", &self.service_key)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("Content-Type", "application/json")
            .header("Prefer", "return=minimal")
            .json(&body)
            .send()
            .await
            .context("update scan status request failed")?;

        if !resp.status().is_success() {
            let status_code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("update scan status failed: {status_code} {body}");
        }
        Ok(())
    }
}
