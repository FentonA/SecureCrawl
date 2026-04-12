use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::scanner::findings::{Finding, FindingType, Severity};

/// Open a TLS connection to `domain:443`, inspect the negotiated protocol
/// version and leaf certificate, and emit findings for weak posture.
///
/// Also checks the HSTS header on the HTTPS response.
pub async fn check(domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let server_name = match ServerName::try_from(domain.to_string()) {
        Ok(n) => n,
        Err(_) => return findings,
    };

    let root_store = {
        let mut rs = rustls::RootCertStore::empty();
        rs.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rs
    };

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = match tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("{domain}:443")),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            findings.push(Finding::new(
                format!("tls://{domain}:443"),
                Severity::Medium,
                FindingType::TlsIssue,
                "Port 443 unreachable",
                "Could not establish a TCP connection to port 443 within 5 seconds.",
                "",
            ));
            return findings;
        }
    };

    let tls_stream = match tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            findings.push(Finding::new(
                format!("tls://{domain}:443"),
                Severity::High,
                FindingType::TlsIssue,
                "TLS handshake failed",
                "Could not complete a TLS handshake. Check cert validity, hostname match, or SNI configuration.",
                "",
            ));
            return findings;
        }
    };

    let (_, conn) = tls_stream.get_ref();

    // Negotiated protocol version
    let version = conn.protocol_version();
    match version {
        Some(rustls::ProtocolVersion::TLSv1_3) => {
            // A — no finding
        }
        Some(rustls::ProtocolVersion::TLSv1_2) => {
            findings.push(Finding::new(
                format!("tls://{domain}:443"),
                Severity::Info,
                FindingType::TlsIssue,
                "TLS 1.3 not negotiated",
                "Server negotiated TLS 1.2. TLS 1.3 is faster and more secure — enable it in your TLS terminator.",
                "TLSv1.2",
            ));
        }
        Some(rustls::ProtocolVersion::TLSv1_1) | Some(rustls::ProtocolVersion::TLSv1_0) => {
            findings.push(Finding::new(
                format!("tls://{domain}:443"),
                Severity::Critical,
                FindingType::TlsIssue,
                "Obsolete TLS version",
                "Server negotiated TLS 1.0 or 1.1. These versions are deprecated and insecure — disable them immediately.",
                format!("{version:?}"),
            ));
        }
        _ => {}
    }

    // Inspect the leaf certificate
    if let Some(certs) = conn.peer_certificates() {
        if let Some(leaf) = certs.first() {
            if let Ok((_, parsed)) = X509Certificate::from_der(leaf.as_ref()) {
                let not_after = parsed.validity().not_after;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let expiry = not_after.timestamp();
                let days_left = (expiry - now) / 86400;

                if days_left < 0 {
                    findings.push(Finding::new(
                        format!("tls://{domain}:443"),
                        Severity::Critical,
                        FindingType::TlsIssue,
                        "TLS certificate expired",
                        "The server's TLS certificate has already expired.",
                        format!("{} days past expiry", -days_left),
                    ));
                } else if days_left < 14 {
                    findings.push(Finding::new(
                        format!("tls://{domain}:443"),
                        Severity::High,
                        FindingType::TlsIssue,
                        "TLS certificate expiring soon",
                        "The TLS certificate expires within 14 days. Renew it immediately to avoid an outage.",
                        format!("{days_left} days remaining"),
                    ));
                } else if days_left < 30 {
                    findings.push(Finding::new(
                        format!("tls://{domain}:443"),
                        Severity::Medium,
                        FindingType::TlsIssue,
                        "TLS certificate expires within 30 days",
                        "Cert renewal is due soon. Automate it if possible.",
                        format!("{days_left} days remaining"),
                    ));
                }
            }
        }
    }

    // Drop the connection cleanly
    let mut stream = tls_stream;
    let _ = stream.shutdown().await;

    // HSTS check — separate cheap HTTP GET, reuse reqwest
    if let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        if let Ok(resp) = client.get(format!("https://{domain}/")).send().await {
            let hsts = resp.headers().get("strict-transport-security");
            match hsts {
                None => {
                    findings.push(Finding::new(
                        format!("tls://{domain}:443"),
                        Severity::Medium,
                        FindingType::TlsIssue,
                        "Missing HSTS header",
                        "Strict-Transport-Security is not set. Clients can be downgraded to HTTP on their first visit.",
                        "",
                    ));
                }
                Some(v) => {
                    let value = v.to_str().unwrap_or("");
                    let lower = value.to_lowercase();

                    // Parse max-age
                    let max_age: Option<u64> = lower
                        .split(';')
                        .find_map(|part| {
                            let p = part.trim();
                            p.strip_prefix("max-age=")
                                .and_then(|s| s.trim_matches('"').parse::<u64>().ok())
                        });

                    if let Some(age) = max_age {
                        if age < 15552000 {
                            findings.push(Finding::new(
                                format!("tls://{domain}:443"),
                                Severity::Low,
                                FindingType::TlsIssue,
                                "HSTS max-age below 6 months",
                                "HSTS max-age is less than 15552000 seconds (~6 months). Longer values give stronger downgrade protection.",
                                value.to_string(),
                            ));
                        }
                    }

                    if !lower.contains("includesubdomains") {
                        findings.push(Finding::new(
                            format!("tls://{domain}:443"),
                            Severity::Info,
                            FindingType::TlsIssue,
                            "HSTS missing includeSubDomains",
                            "HSTS does not apply to subdomains. Add includeSubDomains to protect every subdomain.",
                            value.to_string(),
                        ));
                    }
                }
            }
        }
    }

    findings
}
