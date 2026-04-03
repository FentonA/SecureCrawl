use lazy_static::lazy_static;
use regex::Regex;

use crate::scanner::findings::Severity;

/// A named secret-detection pattern with severity metadata.
pub struct SecretPattern {
    pub name: &'static str,
    pub regex: &'static Regex,
    pub severity: Severity,
    pub description: &'static str,
}

lazy_static! {
    // ── Cloud provider keys ──────────────────────────────────────────
    pub static ref AWS_ACCESS_KEY: Regex =
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    pub static ref AWS_SECRET_KEY: Regex =
        Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap();
    pub static ref GOOGLE_API_KEY: Regex =
        Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap();
    pub static ref HEROKU_API_KEY: Regex =
        Regex::new(r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap();

    // ── Source-control / CI tokens ───────────────────────────────────
    pub static ref GITHUB_TOKEN: Regex =
        Regex::new(r"ghp_[a-zA-Z0-9]{36,40}").unwrap();

    // ── Payment processors ───────────────────────────────────────────
    pub static ref STRIPE_KEY: Regex =
        Regex::new(r"[sr]k_(live|test)_[0-9a-zA-Z]{24,}").unwrap();

    // ── Messaging / SaaS ────────────────────────────────────────────
    pub static ref SLACK_TOKEN: Regex =
        Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}").unwrap();
    pub static ref SLACK_WEBHOOK: Regex =
        Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}").unwrap();
    pub static ref SENDGRID_API_KEY: Regex =
        Regex::new(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}").unwrap();
    pub static ref MAILGUN_API_KEY: Regex =
        Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap();
    pub static ref TWILIO_API_KEY: Regex =
        Regex::new(r"SK[0-9a-fA-F]{32}").unwrap();

    // ── Cryptographic material ───────────────────────────────────────
    pub static ref PRIVATE_KEY: Regex =
        Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap();
    pub static ref JWT_TOKEN: Regex =
        Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap();

    // ── Generic / catch-all ──────────────────────────────────────────
    pub static ref GENERIC_SECRET: Regex =
        Regex::new(r#"(?i)(password|passwd|secret|api_key|apikey|access_key|auth_token|private_key)\s*[=:]\s*['"][A-Za-z0-9/+=@\-_.!#$%]{8,}['"]"#).unwrap();
    pub static ref DATABASE_URL: Regex =
        Regex::new(r#"(?i)(postgres|mysql|mongodb|redis|amqp)(\+\w+)?://[^\s<>"']{10,}"#).unwrap();

    // ── Master list used by the scanner ──────────────────────────────
    pub static ref ALL_PATTERNS: Vec<SecretPattern> = vec![
        SecretPattern {
            name: "AWS Access Key",
            regex: &AWS_ACCESS_KEY,
            severity: Severity::Critical,
            description: "AWS access key ID found in page content",
        },
        SecretPattern {
            name: "AWS Secret Key",
            regex: &AWS_SECRET_KEY,
            severity: Severity::Critical,
            description: "AWS secret access key found in page content",
        },
        SecretPattern {
            name: "GitHub Personal Access Token",
            regex: &GITHUB_TOKEN,
            severity: Severity::Critical,
            description: "GitHub personal access token found in page content",
        },
        SecretPattern {
            name: "Private Key",
            regex: &PRIVATE_KEY,
            severity: Severity::Critical,
            description: "Cryptographic private key found in page content",
        },
        SecretPattern {
            name: "Stripe API Key",
            regex: &STRIPE_KEY,
            severity: Severity::Critical,
            description: "Stripe API key found in page content",
        },
        SecretPattern {
            name: "SendGrid API Key",
            regex: &SENDGRID_API_KEY,
            severity: Severity::Critical,
            description: "SendGrid API key found in page content",
        },
        SecretPattern {
            name: "Google API Key",
            regex: &GOOGLE_API_KEY,
            severity: Severity::High,
            description: "Google API key found in page content",
        },
        SecretPattern {
            name: "Slack Token",
            regex: &SLACK_TOKEN,
            severity: Severity::High,
            description: "Slack API token found in page content",
        },
        SecretPattern {
            name: "Slack Webhook URL",
            regex: &SLACK_WEBHOOK,
            severity: Severity::High,
            description: "Slack incoming webhook URL found in page content",
        },
        SecretPattern {
            name: "Mailgun API Key",
            regex: &MAILGUN_API_KEY,
            severity: Severity::High,
            description: "Mailgun API key found in page content",
        },
        SecretPattern {
            name: "Twilio API Key",
            regex: &TWILIO_API_KEY,
            severity: Severity::High,
            description: "Twilio API key found in page content",
        },
        SecretPattern {
            name: "Heroku API Key",
            regex: &HEROKU_API_KEY,
            severity: Severity::High,
            description: "Heroku API key found in page content",
        },
        SecretPattern {
            name: "Database Connection String",
            regex: &DATABASE_URL,
            severity: Severity::Critical,
            description: "Database connection string with potential credentials found",
        },
        SecretPattern {
            name: "JWT Token",
            regex: &JWT_TOKEN,
            severity: Severity::Medium,
            description: "JSON Web Token found in page content",
        },
        SecretPattern {
            name: "Hardcoded Secret",
            regex: &GENERIC_SECRET,
            severity: Severity::High,
            description: "Hardcoded credential or secret value found",
        },
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key_pattern() {
        assert!(AWS_ACCESS_KEY.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!AWS_ACCESS_KEY.is_match("AKIA123"));
        assert!(!AWS_ACCESS_KEY.is_match("BKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_github_token_pattern() {
        assert!(GITHUB_TOKEN.is_match("ghp_123456789012345678901234567890123456"));
        assert!(GITHUB_TOKEN.is_match("ghp_1234567890123456789012345678901234567890"));
        assert!(!GITHUB_TOKEN.is_match("ghp_short"));
        assert!(!GITHUB_TOKEN.is_match("ghp_12345678901234567890123456789012345"));
        assert!(!GITHUB_TOKEN.is_match("gho_123456789012345678901234567890123456"));
    }

    #[test]
    fn test_private_key_pattern() {
        assert!(PRIVATE_KEY.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(PRIVATE_KEY.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(PRIVATE_KEY.is_match("-----BEGIN EC PRIVATE KEY-----"));
        assert!(!PRIVATE_KEY.is_match("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_aws_secret_in_config_format() {
        let content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(AWS_SECRET_KEY.is_match(content));
    }

    #[test]
    fn test_google_api_key() {
        assert!(GOOGLE_API_KEY.is_match("AIzaSyD-example-key-1234567890abcdefghij"));
        assert!(!GOOGLE_API_KEY.is_match("AIzaShort"));
    }

    #[test]
    fn test_stripe_key() {
        // Build test strings at runtime to avoid triggering GitHub push protection
        let suffix = "FAKEFAKEFAKEFAKEFAKEFAKE";
        let sk_live = format!("sk_live_{suffix}");
        let sk_test = format!("sk_test_{suffix}");
        let rk_live = format!("rk_live_{suffix}");
        assert!(STRIPE_KEY.is_match(&sk_live));
        assert!(STRIPE_KEY.is_match(&sk_test));
        assert!(STRIPE_KEY.is_match(&rk_live));
        assert!(!STRIPE_KEY.is_match("pk_live_short"));
    }

    #[test]
    fn test_slack_token() {
        assert!(SLACK_TOKEN.is_match("xoxb-1234567890-abcdefghij"));
        assert!(SLACK_TOKEN.is_match("xoxp-9876543210-zyxwvutsrq"));
        assert!(!SLACK_TOKEN.is_match("xoxz-invalid"));
    }

    #[test]
    fn test_jwt_token() {
        assert!(
            JWT_TOKEN.is_match(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789jkl012mno345"
            )
        );
        assert!(!JWT_TOKEN.is_match("eyJshort.eyJshort.abc"));
    }

    #[test]
    fn test_generic_secret() {
        assert!(GENERIC_SECRET.is_match(r#"password = "supersecretvalue123""#));
        assert!(GENERIC_SECRET.is_match(r#"api_key: 'my-long-secret-key-value'"#));
        assert!(!GENERIC_SECRET.is_match(r#"password = "short""#));
    }

    #[test]
    fn test_database_url() {
        assert!(DATABASE_URL.is_match("postgres://user:pass@localhost:5432/mydb"));
        assert!(DATABASE_URL.is_match("mongodb://admin:secret@db.example.com/production"));
        assert!(DATABASE_URL.is_match("redis://default:password@cache.internal:6379"));
    }

    #[test]
    fn test_sendgrid_api_key() {
        assert!(
            SENDGRID_API_KEY.is_match(
                "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
            )
        );
    }

    #[test]
    fn test_all_patterns_populated() {
        assert!(ALL_PATTERNS.len() >= 14);
    }
}
