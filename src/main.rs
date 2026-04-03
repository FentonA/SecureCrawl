mod crawler;
mod report;
mod scanner;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio::task::JoinSet;
use url::Url;

use crawler::engine::{PageData, fetch_page};
use crawler::frontier::UrlFrontier;
use crawler::rate_limiter::DomainRateLimiter;
use crawler::robots::RobotsChecker;
use report::{OutputFormat, ScanInfo, ScanReport, Summary};
use scanner::engine::{SENSITIVE_PATHS, SecurityScanner};
use scanner::findings::Finding;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "SecureCrawl")]
#[command(
    version,
    about = "Security-focused web crawler that detects exposed secrets and vulnerabilities"
)]
struct Args {
    /// Target URL to start crawling from
    #[arg(short, long)]
    url: String,

    /// Maximum crawl depth
    #[arg(short, long, default_value_t = 3)]
    depth: usize,

    /// Maximum number of concurrent requests
    #[arg(short, long, default_value_t = 10)]
    concurrency: usize,

    /// Output file path
    #[arg(short, long, default_value = "result.json")]
    output: String,

    /// Output format (json or csv)
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Maximum requests per second per domain
    #[arg(long, default_value_t = 10.0)]
    rate_limit: f64,

    /// HTTP request timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Custom User-Agent string
    #[arg(long, default_value = "SecureCrawl/0.1.0")]
    user_agent: String,

    /// Ignore robots.txt restrictions
    #[arg(long)]
    ignore_robots: bool,

    /// Follow links to external domains
    #[arg(long)]
    cross_domain: bool,
}

// ── Scanner worker ───────────────────────────────────────────────────

/// Runs in a dedicated task. Receives pages via channel, dispatches
/// CPU-bound scanning to the blocking thread pool, and sends findings back.
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

    // Wait for all in-flight scans to complete
    for handle in handles {
        let _ = handle.await;
    }
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let start_time = Instant::now();
    let start_iso = chrono::Utc::now().to_rfc3339();

    // ── Validate seed URL ────────────────────────────────────────────
    let seed_url = Url::parse(&args.url).context("Invalid seed URL")?;
    let base_domain = seed_url.host_str().unwrap_or("").to_string();

    // ── Banner ───────────────────────────────────────────────────────
    println!();
    println!("  SecureCrawl v{}", env!("CARGO_PKG_VERSION"));
    println!("  Target:      {}", args.url);
    println!("  Depth:       {}", args.depth);
    println!("  Concurrency: {}", args.concurrency);
    println!("  Rate limit:  {} req/s", args.rate_limit);
    println!(
        "  Robots.txt:  {}",
        if args.ignore_robots {
            "ignored"
        } else {
            "respected"
        }
    );
    println!();

    // ── Build HTTP client ────────────────────────────────────────────
    let client = reqwest::Client::builder()
        .user_agent(&args.user_agent)
        .timeout(std::time::Duration::from_secs(args.timeout))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("Failed to build HTTP client")?;

    // ── Initialize components ────────────────────────────────────────
    let mut frontier = UrlFrontier::new(args.depth);
    let robots = Arc::new(TokioMutex::new(RobotsChecker::new()));
    let rate_limiter = Arc::new(StdMutex::new(DomainRateLimiter::new(args.rate_limit)));

    // Seed the frontier with the start URL
    frontier.add(seed_url.clone(), 0);

    // Seed sensitive-path probes at depth 0
    for (path, _, _) in SENSITIVE_PATHS {
        if let Ok(probe_url) = seed_url.join(path) {
            frontier.add(probe_url, 0);
        }
    }

    // ── Channels: fetcher → scanner → findings collector ─────────────
    let (page_tx, page_rx) = mpsc::channel::<PageData>(100);
    let (finding_tx, mut finding_rx) = mpsc::channel::<Vec<Finding>>(100);

    // ── Spawn scanner worker ─────────────────────────────────────────
    let scanner_handle = tokio::spawn(scanner_worker(page_rx, finding_tx));

    // ── Progress bar ─────────────────────────────────────────────────
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    progress.enable_steady_tick(std::time::Duration::from_millis(120));

    // ── Crawl stats ──────────────────────────────────────────────────
    let mut pages_crawled: usize = 0;
    let mut urls_discovered: usize = 0;
    let mut error_count: usize = 0;
    let mut bytes_total: u64 = 0;
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut tasks: JoinSet<crawler::engine::CrawlResult> = JoinSet::new();

    // ── Main crawl loop ──────────────────────────────────────────────
    loop {
        // Drain finding channel (non-blocking)
        while let Ok(findings) = finding_rx.try_recv() {
            all_findings.extend(findings);
        }

        // Fill the task set up to the concurrency limit
        while tasks.len() < args.concurrency {
            let Some(crawl_url) = frontier.next() else {
                break;
            };

            let client = client.clone();
            let page_tx = page_tx.clone();
            let robots = robots.clone();
            let rate_limiter = rate_limiter.clone();
            let respect_robots = !args.ignore_robots;

            tasks.spawn(async move {
                // Rate-limit
                let wait = {
                    let domain = crawl_url.url.host_str().unwrap_or("");
                    let mut rl = rate_limiter.lock().unwrap();
                    rl.acquire(domain)
                };
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }

                // Robots.txt check
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

        // If nothing is running and the frontier is empty, we're done
        if tasks.is_empty() {
            break;
        }

        // Wait for the next task to complete
        if let Some(Ok(result)) = tasks.join_next().await {
            pages_crawled += 1;
            bytes_total += result.bytes_downloaded as u64;

            if let Some(ref _err) = result.error {
                error_count += 1;
            }

            // Add discovered URLs to the frontier
            for (url, depth) in result.discovered_urls {
                if !args.cross_domain && url.host_str() != Some(base_domain.as_str()) {
                    continue;
                }
                if frontier.add(url, depth) {
                    urls_discovered += 1;
                }
            }

            progress.set_message(format!(
                "Crawled: {pages_crawled} | Queue: {} | Found: {} | Errors: {error_count}",
                frontier.len(),
                all_findings.len(),
            ));
        }
    }

    // ── Shutdown scanner ─────────────────────────────────────────────
    drop(page_tx); // signals the scanner to stop accepting new pages
    scanner_handle.await.context("Scanner worker panicked")?;

    // Drain remaining findings
    while let Ok(findings) = finding_rx.try_recv() {
        all_findings.extend(findings);
    }

    progress.finish_and_clear();

    // ── Sort findings by severity (critical first) ───────────────────
    all_findings.sort_by_key(|f| match f.severity {
        scanner::findings::Severity::Critical => 0,
        scanner::findings::Severity::High => 1,
        scanner::findings::Severity::Medium => 2,
        scanner::findings::Severity::Low => 3,
        scanner::findings::Severity::Info => 4,
    });

    // ── Build report ─────────────────────────────────────────────────
    let duration = start_time.elapsed();
    let end_iso = chrono::Utc::now().to_rfc3339();

    let report = ScanReport {
        scan_info: ScanInfo {
            target: args.url,
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
    };

    report.print_summary();
    report.save(&args.output, args.format)?;

    Ok(())
}
