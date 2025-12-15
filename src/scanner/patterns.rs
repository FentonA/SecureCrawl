use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    pub static ref AWS_ACCESS_KEY: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    pub static ref AWS_SECRET_KEY: Regex =
        Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap();
    pub static ref GITHUB_TOKEN: Regex = Regex::new(r"ghp_[a-zA-Z0-9]{36,40}").unwrap();
    pub static ref PRIVATE_KEY: Regex =
        Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap();
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
}
