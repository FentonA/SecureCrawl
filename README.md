# SecureCrawl

A high-performance, concurrent web crawler built in Rust that scans websites for security vulnerabilities and exposed secrets. SecureCrawl leverages async I/O with **tokio** for efficient network operations, multi-threaded analysis via **spawn_blocking**, and channel-based pipelines for parallel content processing.

## Features

- **Async concurrent crawling** -- fetches multiple pages simultaneously using tokio + reqwest with configurable concurrency limits
- **Secret detection** -- 15 regex-based detectors for AWS keys, GitHub tokens, Stripe keys, JWTs, database connection strings, private keys, and more
- **Sensitive file probing** -- automatically checks for exposed `.env`, `.git/config`, `.htpasswd`, `backup.sql`, and 17 other sensitive paths
- **Security header analysis** -- flags missing `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, and other security headers
- **Server fingerprinting** -- detects server version disclosure in response headers
- **robots.txt compliance** -- fetches and respects `robots.txt` rules (with `--ignore-robots` override)
- **Per-domain rate limiting** -- token bucket algorithm prevents overwhelming target servers
- **Safe error handling** -- response size limits, request timeouts, and graceful error recovery
- **Structured output** -- JSON and CSV reports with findings categorized by severity (Critical / High / Medium / Low / Info)
- **Progress reporting** -- real-time progress bar showing pages crawled, queue depth, and findings count

## Architecture

```
                          +-------------------+
                          |   CLI (clap)      |
                          |   args & config   |
                          +--------+----------+
                                   |
                          +--------v----------+
                          |   Main Loop       |
                          |   (JoinSet)       |
                          +---+----------+----+
                              |          |
               +--------------+          +---------------+
               |                                         |
    +----------v-----------+              +--------------v-----------+
    |  Fetch Workers       |   PageData   |  Scanner Worker          |
    |  (tokio tasks)       +----channel-->|  (spawn_blocking)        |
    |                      |   (mpsc)     |                          |
    |  - Rate limiting     |              |  - Secret pattern scan   |
    |  - robots.txt check  |              |  - Header analysis       |
    |  - HTML parsing      |              |  - Sensitive path check  |
    |  - Link extraction   |              |  - Server fingerprint    |
    +----------+-----------+              +--------------+------------+
               |                                        |
               | discovered URLs                        | Vec<Finding>
               v                                        v
    +----------+-----------+              +-------------+------------+
    |  URL Frontier        |              |  Report Generator        |
    |  (dedup + depth)     |              |  (JSON / CSV)            |
    +----------------------+              +--------------------------+
```

**Key concurrency model:**
1. The **main loop** owns the URL frontier and dispatches fetch tasks via `JoinSet` (bounded by `--concurrency`)
2. **Fetch workers** (async tokio tasks) handle HTTP requests, rate limiting, robots.txt, and link extraction
3. Fetched pages are sent through an **mpsc channel** to the scanner
4. The **scanner worker** dispatches CPU-bound regex analysis to tokio's **blocking thread pool** via `spawn_blocking`
5. Findings flow back through a second mpsc channel to the main loop for aggregation

## Installation

```bash
# Clone the repository
git clone https://github.com/FentonA/SecureCrawl.git
cd SecureCrawl

# Build in release mode
cargo build --release

# The binary is at target/release/SecureCrawl
```

Requires **Rust 1.85+** (edition 2024).

## Usage

```bash
# Basic scan
securecrawl --url https://example.com

# Deep scan with high concurrency
securecrawl --url https://example.com --depth 5 --concurrency 20

# Output as CSV
securecrawl --url https://example.com --format csv --output findings.csv

# Aggressive scan (ignore robots.txt, follow external links)
securecrawl --url https://example.com --ignore-robots --cross-domain

# Polite scan (low rate limit)
securecrawl --url https://example.com --rate-limit 2 --timeout 15
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | *required* | Target URL to start crawling from |
| `-d, --depth` | `3` | Maximum crawl depth |
| `-c, --concurrency` | `10` | Maximum concurrent requests |
| `-o, --output` | `result.json` | Output file path |
| `-f, --format` | `json` | Output format (`json` or `csv`) |
| `--rate-limit` | `10.0` | Max requests/second per domain |
| `--timeout` | `10` | HTTP request timeout in seconds |
| `--user-agent` | `SecureCrawl/0.1.0` | Custom User-Agent string |
| `--ignore-robots` | `false` | Skip robots.txt restrictions |
| `--cross-domain` | `false` | Follow links to external domains |

## Secret Detection Patterns

| Pattern | Severity | Example Match |
|---------|----------|---------------|
| AWS Access Key | Critical | `AKIA...` |
| AWS Secret Key | Critical | `aws_secret_access_key = ...` |
| GitHub Token | Critical | `ghp_...` |
| Private Key | Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| Stripe API Key | Critical | `sk_live_...` |
| SendGrid API Key | Critical | `SG....` |
| Database URL | Critical | `postgres://user:pass@host/db` |
| Google API Key | High | `AIza...` |
| Slack Token | High | `xoxb-...` |
| Slack Webhook | High | `https://hooks.slack.com/...` |
| Mailgun API Key | High | `key-...` |
| Twilio API Key | High | `SK...` |
| Heroku API Key | High | `heroku...{uuid}` |
| Hardcoded Secret | High | `password = "..."` |
| JWT Token | Medium | `eyJ...` |

## Output Format

### JSON Report

```json
{
  "scan_info": {
    "target": "https://example.com",
    "start_time": "2025-01-15T10:30:00Z",
    "end_time": "2025-01-15T10:35:12Z",
    "duration_seconds": 312,
    "pages_crawled": 150,
    "urls_discovered": 487,
    "errors": 3,
    "bytes_downloaded": 2457600
  },
  "summary": {
    "total_findings": 5,
    "critical": 2,
    "high": 1,
    "medium": 1,
    "low": 1,
    "info": 0
  },
  "findings": [
    {
      "url": "https://example.com/config.js",
      "severity": "critical",
      "finding_type": "exposed_secret",
      "title": "AWS Access Key",
      "description": "AWS access key ID found in page content",
      "evidence": "AKIA...MPLE",
      "line_number": 42
    }
  ]
}
```

### CSV Report

```
url,severity,finding_type,title,description,evidence,line_number
https://example.com/.env,critical,sensitive_file,Sensitive file accessible: /.env,...,
https://example.com/config.js,critical,exposed_secret,AWS Access Key,...,AKIA...MPLE,42
```

## Testing

```bash
# Run all 47 tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test module
cargo test scanner::patterns
cargo test crawler::robots
```

## Project Structure

```
src/
├── main.rs                  # CLI, crawl orchestration, progress display
├── report.rs                # JSON/CSV report generation
├── crawler/
│   ├── mod.rs               # Module exports
│   ├── frontier.rs          # URL queue with dedup & depth control
│   ├── engine.rs            # Async page fetching & link extraction
│   ├── rate_limiter.rs      # Token bucket per-domain rate limiter
│   └── robots.rs            # robots.txt fetcher & parser
└── scanner/
    ├── mod.rs               # Module exports
    ├── findings.rs          # Finding, Severity, FindingType types
    ├── patterns.rs          # 15 secret-detection regex patterns
    └── engine.rs            # Content scanner, header analysis, sensitive path checks
```

## License

MIT
