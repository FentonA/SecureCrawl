use anyhow::Result;
use serde::Serialize;
use std::fs;

use crate::scanner::findings::{Finding, Severity};

/// Output format for the scan report.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Csv,
}

#[derive(Serialize)]
pub struct ScanReport {
    pub scan_info: ScanInfo,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

#[derive(Serialize)]
pub struct ScanInfo {
    pub target: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_seconds: u64,
    pub pages_crawled: usize,
    pub urls_discovered: usize,
    pub errors: usize,
    pub bytes_downloaded: u64,
}

#[derive(Serialize)]
pub struct Summary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self {
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }

        summary
    }
}

impl ScanReport {
    /// Write the report to disk.
    pub fn save(&self, path: &str, format: OutputFormat) -> Result<()> {
        match format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(self)?;
                fs::write(path, json)?;
            }
            OutputFormat::Csv => {
                let mut wtr = csv::Writer::from_path(path)?;
                for finding in &self.findings {
                    wtr.serialize(finding)?;
                }
                wtr.flush()?;
            }
        }
        println!("\nReport saved to: {path}");
        Ok(())
    }

    /// Print a human-readable summary to stdout.
    pub fn print_summary(&self) {
        let bar = "=".repeat(64);
        let thin = "-".repeat(64);

        println!("\n{bar}");
        println!("  SECURECRAWL SCAN RESULTS");
        println!("{bar}");
        println!("  Target:      {}", self.scan_info.target);
        println!("  Duration:    {}s", self.scan_info.duration_seconds);
        println!("  Pages:       {}", self.scan_info.pages_crawled);
        println!("  URLs found:  {}", self.scan_info.urls_discovered);
        println!("  Errors:      {}", self.scan_info.errors);
        println!(
            "  Downloaded:  {:.2} MB",
            self.scan_info.bytes_downloaded as f64 / (1024.0 * 1024.0)
        );
        println!("{thin}");

        if self.findings.is_empty() {
            println!("  No security findings detected.");
        } else {
            println!("  FINDINGS: {} total", self.summary.total_findings);
            println!(
                "  Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
                self.summary.critical,
                self.summary.high,
                self.summary.medium,
                self.summary.low,
                self.summary.info
            );
            println!("{thin}");

            for finding in &self.findings {
                let sev = match finding.severity {
                    Severity::Critical => "CRIT",
                    Severity::High => "HIGH",
                    Severity::Medium => " MED",
                    Severity::Low => " LOW",
                    Severity::Info => "INFO",
                };
                println!("  [{sev}] {} - {}", finding.title, finding.url);
                if !finding.evidence.is_empty() && finding.evidence != "Header not present" {
                    print!("         Evidence: {}", finding.evidence);
                    if let Some(line) = finding.line_number {
                        print!(" (line {line})");
                    }
                    println!();
                }
            }
        }

        println!("{bar}");
    }
}
