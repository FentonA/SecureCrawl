use std::collections::{HashSet, VecDeque};
use url::Url;

#[derive(Debug, Clone)]
pub struct CrawlUrl {
    pub url: Url,
    pub depth: usize,
}

pub struct UrlFrontier {
    queue: VecDeque<CrawlUrl>,
    visited: HashSet<String>,
    max_depth: usize,
}

impl UrlFrontier {
    pub fn new(max_depth: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            visited: HashSet::new(),
            max_depth,
        }
    }

    pub fn add(&mut self, url: Url, depth: usize) -> bool {
        if depth > self.max_depth {
            return false;
        }
        let mut normalized = url.clone();
        normalized.set_fragment(None);
        let url_string = normalized.to_string();

        if self.visited.contains(&url_string) {
            return false;
        }

        self.visited.insert(url_string);
        self.queue.push_back(CrawlUrl {
            url: normalized,
            depth,
        });
        true
    }

    pub fn next(&mut self) -> Option<CrawlUrl> {
        self.queue.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_frontier_is_empty() {
        let frontier = UrlFrontier::new(3);
        assert!(frontier.is_empty());
        assert_eq!(frontier.len(), 0);
    }

    #[test]
    fn test_add_url_returns_true_for_new_url() {
        let mut frontier = UrlFrontier::new(3);
        let url = Url::parse("https://example.com").unwrap();

        assert!(frontier.add(url, 0));
        assert_eq!(frontier.len(), 1);
    }

    #[test]
    fn test_add_duplicate_url_returns_false() {
        let mut frontier = UrlFrontier::new(3);
        let url1 = Url::parse("https://example.com").unwrap();
        let url2 = Url::parse("https://example.com").unwrap();

        assert!(frontier.add(url1, 0));
        assert!(!frontier.add(url2, 0));
        assert_eq!(frontier.len(), 1);
    }

    #[test]
    fn test_add_url_with_fragment_is_deduplicated() {
        let mut frontier = UrlFrontier::new(3);
        let url1 = Url::parse("https://example.com/page");
        let url2 = Url::parse("https://example.com/page#section").unwrap();

        assert!(frontier.add(url1.expect("Could not parse url"), 0));
        assert!(
            !frontier.add(url2, 0),
            "URLS with fragments should be treated as duplicates"
        );
        assert_eq!(frontier.len(), 1)
    }

    #[test]
    fn test_respects_max_depth() {
        let mut frontier = UrlFrontier::new(2);
        let url = Url::parse("https://example.com").unwrap();

        assert!(frontier.add(url.clone(), 2));
        assert!(
            !frontier.add(url.clone(), 3),
            "Should rejet urls beyond max depth"
        );
    }

    #[test]
    fn test_next_returns_urls_in_fifo_order() {
        let mut frontier = UrlFrontier::new(3);
        let url1 = Url::parse("https://example.com/1").unwrap();
        let url2 = Url::parse("https://example.com/2").unwrap();

        frontier.add(url1.clone(), 0);
        frontier.add(url2.clone(), 0);

        let first = frontier.next().unwrap();
        assert_eq!(first.url, url1);

        let second = frontier.next().unwrap();
        assert_eq!(second.url, url2);

        assert!(frontier.next().is_none());
    }

    #[test]
    fn test_next_preserves_depth() {
        let mut frontier = UrlFrontier::new(3);
        let url = Url::parse("https://example.com").unwrap();

        frontier.add(url, 2);
        let crawl_url = frontier.next().unwrap();

        assert_eq!(crawl_url.depth, 2);
    }
}
