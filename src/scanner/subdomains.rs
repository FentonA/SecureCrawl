use std::collections::HashSet;
use std::time::Duration;

use serde::Deserialize;

use crate::scanner::findings::{Finding, FindingType, Severity};

const CRT_SH_URL: &str = "https://crt.sh/";
const MAX_SUBDOMAINS: usize = 50;

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Query crt.sh (certificate transparency logs) for subdomains of `domain`.
///
/// Returns a finding per distinct subdomain, capped at MAX_SUBDOMAINS so a
/// single scan on a huge domain doesn't produce thousands of info findings.
pub async fn discover(domain: &str) -> Vec<Finding> {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("SecureCrawl/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let response = match client
        .get(CRT_SH_URL)
        .query(&[("q", &format!("%.{domain}")), ("output", &"json".to_string())])
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    if !response.status().is_success() {
        return Vec::new();
    }

    let entries: Vec<CrtShEntry> = match response.json().await {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut discovered: HashSet<String> = HashSet::new();
    for entry in entries {
        for raw in entry.name_value.split('\n') {
            let sub = raw.trim().trim_start_matches("*.").to_lowercase();
            if sub.is_empty() || !sub.ends_with(domain) || sub == domain {
                continue;
            }
            discovered.insert(sub);
        }
    }

    let mut sorted: Vec<String> = discovered.into_iter().collect();
    sorted.sort();
    sorted.truncate(MAX_SUBDOMAINS);

    sorted
        .into_iter()
        .map(|sub| {
            Finding::new(
                format!("https://{sub}"),
                Severity::Info,
                FindingType::SubdomainDiscovered,
                format!("Subdomain found: {sub}"),
                "Discovered via certificate transparency logs (crt.sh). Verify this subdomain is still in use and not an abandoned asset.",
                sub,
            )
        })
        .collect()
}
