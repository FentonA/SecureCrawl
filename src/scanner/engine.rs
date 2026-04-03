use reqwest::header::HeaderMap;

use crate::scanner::findings::{Finding, FindingType, Severity};
use crate::scanner::patterns::ALL_PATTERNS;

/// Well-known paths that should not be publicly accessible.
pub const SENSITIVE_PATHS: &[(&str, &str, Severity)] = &[
    (
        "/.env",
        "Environment configuration file exposed",
        Severity::Critical,
    ),
    (
        "/.git/config",
        "Git configuration file exposed",
        Severity::Critical,
    ),
    (
        "/.git/HEAD",
        "Git HEAD reference exposed",
        Severity::Critical,
    ),
    (
        "/.htpasswd",
        "Apache password file exposed",
        Severity::Critical,
    ),
    (
        "/wp-config.php",
        "WordPress configuration exposed",
        Severity::Critical,
    ),
    (
        "/.aws/credentials",
        "AWS credentials file exposed",
        Severity::Critical,
    ),
    (
        "/backup.sql",
        "Database backup file exposed",
        Severity::Critical,
    ),
    (
        "/dump.sql",
        "Database dump file exposed",
        Severity::Critical,
    ),
    (
        "/.npmrc",
        "NPM configuration (may contain auth tokens)",
        Severity::High,
    ),
    (
        "/.dockerenv",
        "Docker environment indicator",
        Severity::Medium,
    ),
    (
        "/docker-compose.yml",
        "Docker Compose config (may contain secrets)",
        Severity::Medium,
    ),
    (
        "/.htaccess",
        "Apache configuration file exposed",
        Severity::Medium,
    ),
    (
        "/phpinfo.php",
        "PHP info page exposes server configuration",
        Severity::Medium,
    ),
    (
        "/server-status",
        "Apache server-status page exposed",
        Severity::Medium,
    ),
    ("/elmah.axd", "ELMAH error log exposed", Severity::Medium),
    (
        "/.DS_Store",
        "macOS directory metadata exposed",
        Severity::Low,
    ),
    (
        "/crossdomain.xml",
        "Flash cross-domain policy file",
        Severity::Low,
    ),
    ("/robots.txt", "Robots.txt file", Severity::Info),
    ("/sitemap.xml", "Sitemap file", Severity::Info),
    (
        "/.well-known/security.txt",
        "Security contact information",
        Severity::Info,
    ),
];

/// Security headers every response should include.
const SECURITY_HEADERS: &[(&str, &str, Severity)] = &[
    (
        "content-security-policy",
        "Content-Security-Policy",
        Severity::Medium,
    ),
    ("x-frame-options", "X-Frame-Options", Severity::Medium),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        Severity::Low,
    ),
    (
        "strict-transport-security",
        "Strict-Transport-Security",
        Severity::Medium,
    ),
    ("x-xss-protection", "X-XSS-Protection", Severity::Low),
    ("referrer-policy", "Referrer-Policy", Severity::Low),
    ("permissions-policy", "Permissions-Policy", Severity::Low),
];

/// Stateless security scanner applied to every fetched page.
pub struct SecurityScanner;

impl SecurityScanner {
    /// Run all scan checks against a single page.
    pub fn scan_page(url: &str, body: &str, headers: &HeaderMap, status: u16) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Always scan body content for leaked secrets
        findings.extend(Self::scan_content(url, body));

        if status == 200 {
            // Check if this is a known sensitive path
            if let Some(f) = Self::check_sensitive_path(url) {
                findings.push(f);
            }

            // Check security headers only on successful HTML responses
            let is_html = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .contains("text/html");

            if is_html {
                findings.extend(Self::scan_headers(url, headers));
            }
        }

        // Check for server version disclosure on any response
        if let Some(f) = Self::check_server_disclosure(url, headers) {
            findings.push(f);
        }

        findings
    }

    /// Apply all secret-detection regex patterns to page body, line by line.
    fn scan_content(url: &str, body: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in body.lines().enumerate() {
            for pattern in ALL_PATTERNS.iter() {
                if let Some(m) = pattern.regex.find(line) {
                    findings.push(
                        Finding::new(
                            url,
                            pattern.severity,
                            FindingType::ExposedSecret,
                            pattern.name,
                            pattern.description,
                            redact(m.as_str()),
                        )
                        .with_line(line_num + 1),
                    );
                }
            }
        }

        findings
    }

    /// Check for missing security headers.
    fn scan_headers(url: &str, headers: &HeaderMap) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (header_key, display_name, severity) in SECURITY_HEADERS {
            if !headers.contains_key(*header_key) {
                findings.push(Finding::new(
                    url,
                    *severity,
                    FindingType::MissingSecurityHeader,
                    format!("Missing {display_name} header"),
                    format!("The {display_name} header is not set on this response"),
                    "Header not present",
                ));
            }
        }

        findings
    }

    /// Flag accessible sensitive files.
    fn check_sensitive_path(url: &str) -> Option<Finding> {
        for (path, description, severity) in SENSITIVE_PATHS {
            // Match against path component only, ignoring query/fragment
            if url_path_matches(url, path) {
                // Skip purely informational paths (robots.txt, sitemap, security.txt)
                if *severity == Severity::Info {
                    return None;
                }
                return Some(Finding::new(
                    url,
                    *severity,
                    FindingType::SensitiveFile,
                    format!("Sensitive file accessible: {path}"),
                    *description,
                    format!("HTTP 200 returned for {path}"),
                ));
            }
        }
        None
    }

    /// Check for server software version disclosure.
    fn check_server_disclosure(url: &str, headers: &HeaderMap) -> Option<Finding> {
        let server = headers.get("server")?.to_str().ok()?;
        if server.contains('/') {
            Some(Finding::new(
                url,
                Severity::Low,
                FindingType::InformationDisclosure,
                "Server version disclosure",
                "The Server header reveals software and version information",
                server,
            ))
        } else {
            None
        }
    }
}

/// Check if a full URL's path ends with the given sensitive path.
fn url_path_matches(url: &str, path: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url) {
        parsed.path().ends_with(path)
    } else {
        url.contains(path)
    }
}

/// Redact the middle of a secret, keeping the first and last 4 characters visible.
pub fn redact(secret: &str) -> String {
    let len = secret.len();
    if len <= 8 {
        return "*".repeat(len);
    }
    let show = 4;
    format!("{}...{}", &secret[..show], &secret[len - show..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_short_secret() {
        assert_eq!(redact("abc"), "***");
        assert_eq!(redact("12345678"), "********");
    }

    #[test]
    fn test_redact_long_secret() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA...MPLE");
        assert_eq!(
            redact("ghp_abcdefghij1234567890abcdefghij123456"),
            "ghp_...3456"
        );
    }

    #[test]
    fn test_scan_content_finds_aws_key() {
        let body = "some config\naws_key = AKIAIOSFODNN7EXAMPLE\nend";
        let findings = SecurityScanner::scan_content("https://example.com/config.js", body);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "AWS Access Key");
        assert_eq!(findings[0].line_number, Some(2));
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_scan_content_finds_private_key() {
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";
        let findings = SecurityScanner::scan_content("https://example.com/key", body);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "Private Key");
    }

    #[test]
    fn test_scan_content_clean_page() {
        let body = "<html><body>Hello World</body></html>";
        let findings = SecurityScanner::scan_content("https://example.com/", body);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_sensitive_path_env() {
        let finding = SecurityScanner::check_sensitive_path("https://example.com/.env");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.finding_type, FindingType::SensitiveFile);
    }

    #[test]
    fn test_check_sensitive_path_normal() {
        let finding = SecurityScanner::check_sensitive_path("https://example.com/about");
        assert!(finding.is_none());
    }

    #[test]
    fn test_check_sensitive_path_info_skipped() {
        let finding = SecurityScanner::check_sensitive_path("https://example.com/robots.txt");
        assert!(finding.is_none());
    }

    #[test]
    fn test_scan_headers_missing() {
        let headers = HeaderMap::new();
        let findings = SecurityScanner::scan_headers("https://example.com/", &headers);
        assert!(findings.len() >= 5);
    }

    #[test]
    fn test_scan_headers_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "default-src 'self'".parse().unwrap(),
        );
        headers.insert("x-frame-options", "DENY".parse().unwrap());
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        headers.insert(
            "strict-transport-security",
            "max-age=31536000".parse().unwrap(),
        );
        headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
        headers.insert("referrer-policy", "no-referrer".parse().unwrap());
        headers.insert("permissions-policy", "camera=()".parse().unwrap());

        let findings = SecurityScanner::scan_headers("https://example.com/", &headers);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_server_disclosure_with_version() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "Apache/2.4.41".parse().unwrap());
        let finding = SecurityScanner::check_server_disclosure("https://example.com/", &headers);
        assert!(finding.is_some());
        assert!(finding.unwrap().evidence.contains("Apache/2.4.41"));
    }

    #[test]
    fn test_server_disclosure_without_version() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "cloudflare".parse().unwrap());
        let finding = SecurityScanner::check_server_disclosure("https://example.com/", &headers);
        assert!(finding.is_none());
    }
}
