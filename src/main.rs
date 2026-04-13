use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use securecrawl::{OutputFormat, ScanOpts, run_scan};

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} [{elapsed_precise}] Scanning...")
            .unwrap(),
    );
    progress.enable_steady_tick(std::time::Duration::from_millis(120));

    let opts = ScanOpts {
        url: args.url,
        depth: args.depth,
        concurrency: args.concurrency,
        rate_limit: args.rate_limit,
        timeout: args.timeout,
        user_agent: args.user_agent,
        ignore_robots: args.ignore_robots,
        cross_domain: args.cross_domain,
    };

    let report = run_scan(opts).await?;

    progress.finish_and_clear();

    report.print_summary();
    report.save(&args.output, args.format)?;

    Ok(())
}
