use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    ExposedSecret,
    SensitiveFile,
    MissingSecurityHeader,
    InformationDisclosure,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::ExposedSecret => write!(f, "Exposed Secret"),
            FindingType::SensitiveFile => write!(f, "Sensitive File"),
            FindingType::MissingSecurityHeader => write!(f, "Missing Security Header"),
            FindingType::InformationDisclosure => write!(f, "Information Disclosure"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub url: String,
    pub severity: Severity,
    pub finding_type: FindingType,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub line_number: Option<usize>,
}

impl Finding {
    pub fn new(
        url: impl Into<String>,
        severity: Severity,
        finding_type: FindingType,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            severity,
            finding_type,
            title: title.into(),
            description: description.into(),
            evidence: evidence.into(),
            line_number: None,
        }
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }
}
