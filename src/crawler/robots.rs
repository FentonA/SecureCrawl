use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

struct RobotsRules {
    disallow: Vec<String>,
    allow: Vec<String>,
}

impl RobotsRules {
    fn is_path_allowed(&self, path: &str) -> bool {
        let mut best_allow: Option<usize> = None;
        let mut best_disallow: Option<usize> = None;

        for rule in &self.allow {
            if path.starts_with(rule.as_str()) {
                let len = rule.len();
                if best_allow.is_none_or(|l| len > l) {
                    best_allow = Some(len);
                }
            }
        }

        for rule in &self.disallow {
            if path.starts_with(rule.as_str()) {
                let len = rule.len();
                if best_disallow.is_none_or(|l| len > l) {
                    best_disallow = Some(len);
                }
            }
        }

        match (best_allow, best_disallow) {
            (Some(a), Some(d)) => a >= d,
            (None, Some(_)) => false,
            _ => true,
        }
    }
}

/// Fetches, caches, and checks robots.txt rules per origin.
pub struct RobotsChecker {
    cache: HashMap<String, RobotsRules>,
}

impl RobotsChecker {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Check whether a URL is allowed by the cached robots.txt rules.
    /// Returns `true` if the origin hasn't been fetched yet (fail-open).
    pub fn is_allowed(&self, url: &Url) -> bool {
        let origin = Self::origin(url);
        match self.cache.get(&origin) {
            Some(rules) => rules.is_path_allowed(url.path()),
            None => true,
        }
    }

    /// Fetch and cache robots.txt for the given URL's origin if not already cached.
    pub async fn fetch_if_needed(&mut self, url: &Url, client: &Client) {
        let origin = Self::origin(url);
        if self.cache.contains_key(&origin) {
            return;
        }

        let robots_url = format!("{}/robots.txt", origin);
        let rules = match client
            .get(&robots_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().await.unwrap_or_default();
                Self::parse(&text)
            }
            _ => RobotsRules {
                disallow: vec![],
                allow: vec![],
            },
        };
        self.cache.insert(origin, rules);
    }

    fn origin(url: &Url) -> String {
        format!(
            "{}://{}",
            url.scheme(),
            url.host_str().unwrap_or("localhost")
        )
    }

    fn parse(content: &str) -> RobotsRules {
        let mut disallow = Vec::new();
        let mut allow = Vec::new();
        let mut in_wildcard_section = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let lower = line.to_lowercase();

            if lower.starts_with("user-agent:") {
                let agent = line["user-agent:".len()..].trim();
                in_wildcard_section = agent == "*";
            } else if in_wildcard_section {
                if lower.starts_with("disallow:") {
                    let path = line["disallow:".len()..].trim();
                    if !path.is_empty() {
                        disallow.push(path.to_string());
                    }
                } else if lower.starts_with("allow:") {
                    let path = line["allow:".len()..].trim();
                    if !path.is_empty() {
                        allow.push(path.to_string());
                    }
                }
            }
        }

        RobotsRules { disallow, allow }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_robots() {
        let content = "\
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /admin/public/
";
        let rules = RobotsChecker::parse(content);
        assert!(rules.is_path_allowed("/"));
        assert!(rules.is_path_allowed("/about"));
        assert!(!rules.is_path_allowed("/admin/"));
        assert!(!rules.is_path_allowed("/admin/settings"));
        assert!(rules.is_path_allowed("/admin/public/"));
        assert!(rules.is_path_allowed("/admin/public/page"));
        assert!(!rules.is_path_allowed("/private/secret"));
    }

    #[test]
    fn test_empty_robots_allows_all() {
        let rules = RobotsChecker::parse("");
        assert!(rules.is_path_allowed("/anything"));
    }

    #[test]
    fn test_disallow_root_blocks_all() {
        let content = "\
User-agent: *
Disallow: /
";
        let rules = RobotsChecker::parse(content);
        assert!(!rules.is_path_allowed("/"));
        assert!(!rules.is_path_allowed("/page"));
    }

    #[test]
    fn test_ignores_other_user_agents() {
        let content = "\
User-agent: Googlebot
Disallow: /secret/

User-agent: *
Disallow: /admin/
";
        let rules = RobotsChecker::parse(content);
        assert!(rules.is_path_allowed("/secret/"));
        assert!(!rules.is_path_allowed("/admin/"));
    }

    #[test]
    fn test_comments_and_blank_lines() {
        let content = "\
# This is a comment
User-agent: *

# Block admin
Disallow: /admin/
";
        let rules = RobotsChecker::parse(content);
        assert!(!rules.is_path_allowed("/admin/page"));
    }

    #[test]
    fn test_unknown_origin_allows() {
        let checker = RobotsChecker::new();
        let url = Url::parse("https://unknown.com/page").unwrap();
        assert!(checker.is_allowed(&url));
    }
}
