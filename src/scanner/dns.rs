use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

use crate::scanner::findings::{Finding, FindingType, Severity};

/// Run all DNS security posture checks against a domain.
///
/// Checks: SPF, DMARC, CAA, DNSSEC. Returns findings for each
/// missing or weak configuration.
pub async fn check(domain: &str) -> Vec<Finding> {
    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let (spf, dmarc, caa, dnssec) = tokio::join!(
        check_spf(&resolver, domain),
        check_dmarc(&resolver, domain),
        check_caa(&resolver, domain),
        check_dnssec(&resolver, domain),
    );

    let mut findings = Vec::new();
    findings.extend(spf);
    findings.extend(dmarc);
    findings.extend(caa);
    findings.extend(dnssec);
    findings
}

fn dns_loc(domain: &str) -> String {
    format!("dns://{domain}")
}

async fn check_spf(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let txt_records = match resolver.txt_lookup(domain).await {
        Ok(r) => r,
        Err(_) => {
            return vec![Finding::new(
                dns_loc(domain),
                Severity::Medium,
                FindingType::DnsMisconfiguration,
                "Missing SPF record",
                "No TXT records at the domain apex. Without SPF, attackers can spoof emails from your domain.",
                "",
            )];
        }
    };

    let spf: Option<String> = txt_records
        .iter()
        .find_map(|r| {
            let joined = r
                .iter()
                .filter_map(|d| std::str::from_utf8(d).ok())
                .collect::<Vec<_>>()
                .join("");
            joined.starts_with("v=spf1").then_some(joined)
        });

    let Some(spf_value) = spf else {
        return vec![Finding::new(
            dns_loc(domain),
            Severity::Medium,
            FindingType::DnsMisconfiguration,
            "Missing SPF record",
            "No v=spf1 TXT record found. Without SPF, attackers can spoof emails from your domain.",
            "",
        )];
    };

    let mut findings = Vec::new();
    let lower = spf_value.to_lowercase();
    let has_strict_all = lower.contains("-all");
    let has_soft_all = lower.contains("~all");

    if !has_strict_all && !has_soft_all {
        findings.push(Finding::new(
            dns_loc(domain),
            Severity::Medium,
            FindingType::DnsMisconfiguration,
            "Weak SPF policy",
            "SPF record does not end with -all or ~all, allowing unauthorized senders.",
            spf_value.clone(),
        ));
    } else if has_soft_all && !has_strict_all {
        findings.push(Finding::new(
            dns_loc(domain),
            Severity::Low,
            FindingType::DnsMisconfiguration,
            "Soft-fail SPF policy",
            "SPF uses ~all (soft fail). Strict failure (-all) is recommended once you have confidence in your sender list.",
            spf_value.clone(),
        ));
    }

    findings
}

async fn check_dmarc(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let dmarc_domain = format!("_dmarc.{domain}");
    let txt_records = match resolver.txt_lookup(&dmarc_domain).await {
        Ok(r) => r,
        Err(_) => {
            return vec![Finding::new(
                dns_loc(domain),
                Severity::High,
                FindingType::DnsMisconfiguration,
                "Missing DMARC record",
                "No DMARC record found at _dmarc. Without DMARC, receivers cannot detect spoofed mail from your domain.",
                "",
            )];
        }
    };

    let dmarc: Option<String> = txt_records.iter().find_map(|r| {
        let joined = r
            .iter()
            .filter_map(|d| std::str::from_utf8(d).ok())
            .collect::<Vec<_>>()
            .join("");
        joined.starts_with("v=DMARC1").then_some(joined)
    });

    let Some(dmarc_value) = dmarc else {
        return vec![Finding::new(
            dns_loc(domain),
            Severity::High,
            FindingType::DnsMisconfiguration,
            "Missing DMARC record",
            "No v=DMARC1 TXT record found at _dmarc. Without DMARC, receivers cannot detect spoofed mail.",
            "",
        )];
    };

    let lower = dmarc_value.to_lowercase();
    let mut findings = Vec::new();

    if lower.contains("p=none") {
        findings.push(Finding::new(
            dns_loc(domain),
            Severity::Medium,
            FindingType::DnsMisconfiguration,
            "DMARC policy is monitor-only",
            "DMARC is set to p=none, which only reports but does not block spoofed mail. Move to p=quarantine or p=reject once you have observability.",
            dmarc_value.clone(),
        ));
    } else if lower.contains("p=quarantine") {
        findings.push(Finding::new(
            dns_loc(domain),
            Severity::Low,
            FindingType::DnsMisconfiguration,
            "DMARC policy is quarantine (not reject)",
            "DMARC is set to p=quarantine. Strict blocking (p=reject) is recommended once you have confidence.",
            dmarc_value.clone(),
        ));
    }

    findings
}

async fn check_caa(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let txt_like = resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CAA).await;

    if let Ok(records) = txt_like {
        if records.iter().next().is_some() {
            return Vec::new();
        }
    }

    vec![Finding::new(
        dns_loc(domain),
        Severity::Low,
        FindingType::DnsMisconfiguration,
        "Missing CAA record",
        "No CAA (Certificate Authority Authorization) record found. CAA restricts which CAs can issue certs for your domain, mitigating mis-issuance.",
        "",
    )]
}

async fn check_dnssec(resolver: &TokioAsyncResolver, domain: &str) -> Vec<Finding> {
    let dnskey = resolver
        .lookup(domain, hickory_resolver::proto::rr::RecordType::DNSKEY)
        .await;

    if let Ok(records) = dnskey {
        if records.iter().next().is_some() {
            return Vec::new();
        }
    }

    vec![Finding::new(
        dns_loc(domain),
        Severity::Low,
        FindingType::DnsMisconfiguration,
        "DNSSEC not enabled",
        "No DNSKEY records found. DNSSEC prevents DNS spoofing/cache poisoning attacks against your domain.",
        "",
    )]
}
