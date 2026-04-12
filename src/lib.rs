pub mod crawler;
pub mod report;
pub mod scanner;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio::task::JoinSet;
use url::Url;

pub use report::{OutputFormat, ScanInfo, ScanReport, Summary};
pub use scanner::findings::{Finding, FindingType, Severity};

use crawler::engine::{PageData, fetch_page};
use crawler::frontier::UrlFrontier;
use crawler::rate_limiter::DomainRateLimiter;
use crawler::robots::RobotsChecker;
use scanner::engine::{SENSITIVE_PATHS, SecurityScanner};
use scanner::{dns, subdomains, tls};

#[derive(Debug, Clone)]
pub struct ScanOpts {
    pub url: String,
    pub depth: usize,
    pub concurrency: usize,
    pub rate_limit: f64,
    pub timeout: u64,
    pub user_agent: String,
    pub ignore_robots: bool,
    pub cross_domain: bool,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            url: String::new(),
            depth: 3,
            concurrency: 10,
            rate_limit: 10.0,
            timeout: 10,
            user_agent: format!("SecureCrawl/{}", env!("CARGO_PKG_VERSION")),
            ignore_robots: false,
            cross_domain: false,
        }
    }
}

async fn scanner_worker(
    mut page_rx: mpsc::Receiver<PageData>,
    finding_tx: mpsc::Sender<Vec<Finding>>,
) {
    let mut handles = Vec::new();

    while let Some(page) = page_rx.recv().await {
        let tx = finding_tx.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let findings =
                SecurityScanner::scan_page(&page.url, &page.body, &page.headers, page.status);
            if !findings.is_empty() {
                let _ = tx.blocking_send(findings);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

/// Run a full crawl + scan against the target described by `opts`.
///
/// Prints nothing to stdout — callers can wrap with their own progress UI.
pub async fn run_scan(opts: ScanOpts) -> Result<ScanReport> {
    let start_time = Instant::now();
    let start_iso = chrono::Utc::now().to_rfc3339();

    let seed_url = Url::parse(&opts.url).context("Invalid seed URL")?;
    let base_domain = seed_url.host_str().unwrap_or("").to_string();

    // ── Kick off domain-level checks in parallel with the crawl ──────
    let dns_handle = tokio::spawn({
        let d = base_domain.clone();
        async move { dns::check(&d).await }
    });
    let tls_handle = tokio::spawn({
        let d = base_domain.clone();
        async move { tls::check(&d).await }
    });
    let subdomains_handle = tokio::spawn({
        let d = base_domain.clone();
        async move { subdomains::discover(&d).await }
    });

    let client = reqwest::Client::builder()
        .user_agent(&opts.user_agent)
        .timeout(std::time::Duration::from_secs(opts.timeout))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("Failed to build HTTP client")?;

    let mut frontier = UrlFrontier::new(opts.depth);
    let robots = Arc::new(TokioMutex::new(RobotsChecker::new()));
    let rate_limiter = Arc::new(StdMutex::new(DomainRateLimiter::new(opts.rate_limit)));

    frontier.add(seed_url.clone(), 0);

    for (path, _, _) in SENSITIVE_PATHS {
        if let Ok(probe_url) = seed_url.join(path) {
            frontier.add(probe_url, 0);
        }
    }

    let (page_tx, page_rx) = mpsc::channel::<PageData>(100);
    let (finding_tx, mut finding_rx) = mpsc::channel::<Vec<Finding>>(100);

    let scanner_handle = tokio::spawn(scanner_worker(page_rx, finding_tx));

    let mut pages_crawled: usize = 0;
    let mut urls_discovered: usize = 0;
    let mut error_count: usize = 0;
    let mut bytes_total: u64 = 0;
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut tasks: JoinSet<crawler::engine::CrawlResult> = JoinSet::new();

    loop {
        while let Ok(findings) = finding_rx.try_recv() {
            all_findings.extend(findings);
        }

        while tasks.len() < opts.concurrency {
            let Some(crawl_url) = frontier.next() else {
                break;
            };

            let client = client.clone();
            let page_tx = page_tx.clone();
            let robots = robots.clone();
            let rate_limiter = rate_limiter.clone();
            let respect_robots = !opts.ignore_robots;

            tasks.spawn(async move {
                let wait = {
                    let domain = crawl_url.url.host_str().unwrap_or("");
                    let mut rl = rate_limiter.lock().unwrap();
                    rl.acquire(domain)
                };
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }

                if respect_robots {
                    let mut rb = robots.lock().await;
                    rb.fetch_if_needed(&crawl_url.url, &client).await;
                    if !rb.is_allowed(&crawl_url.url) {
                        return crawler::engine::CrawlResult {
                            discovered_urls: vec![],
                            bytes_downloaded: 0,
                            error: Some("Blocked by robots.txt".into()),
                        };
                    }
                }

                fetch_page(&client, crawl_url.url.clone(), crawl_url.depth, &page_tx).await
            });
        }

        if tasks.is_empty() {
            break;
        }

        if let Some(Ok(result)) = tasks.join_next().await {
            pages_crawled += 1;
            bytes_total += result.bytes_downloaded as u64;

            if result.error.is_some() {
                error_count += 1;
            }

            for (url, depth) in result.discovered_urls {
                if !opts.cross_domain && url.host_str() != Some(base_domain.as_str()) {
                    continue;
                }
                if frontier.add(url, depth) {
                    urls_discovered += 1;
                }
            }
        }
    }

    drop(page_tx);
    scanner_handle.await.context("Scanner worker panicked")?;

    while let Ok(findings) = finding_rx.try_recv() {
        all_findings.extend(findings);
    }

    // ── Collect domain-level check results ───────────────────────────
    if let Ok(dns_findings) = dns_handle.await {
        all_findings.extend(dns_findings);
    }
    if let Ok(tls_findings) = tls_handle.await {
        all_findings.extend(tls_findings);
    }
    if let Ok(subdomain_findings) = subdomains_handle.await {
        all_findings.extend(subdomain_findings);
    }

    all_findings.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });

    let duration = start_time.elapsed();
    let end_iso = chrono::Utc::now().to_rfc3339();

    Ok(ScanReport {
        scan_info: ScanInfo {
            target: opts.url,
            start_time: start_iso,
            end_time: end_iso,
            duration_seconds: duration.as_secs(),
            pages_crawled,
            urls_discovered,
            errors: error_count,
            bytes_downloaded: bytes_total,
        },
        summary: Summary::from_findings(&all_findings),
        findings: all_findings,
    })
}
