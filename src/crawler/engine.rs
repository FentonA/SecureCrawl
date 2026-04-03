use reqwest::header::HeaderMap;
use scraper::{Html, Selector};
use url::Url;

/// Data sent from the fetcher to the scanner via mpsc channel.
pub struct PageData {
    pub url: String,
    pub body: String,
    pub headers: HeaderMap,
    pub status: u16,
}

/// Result returned by a fetch task back to the main crawl loop.
pub struct CrawlResult {
    pub discovered_urls: Vec<(Url, usize)>,
    pub bytes_downloaded: usize,
    pub error: Option<String>,
}

/// Maximum response body size (10 MB).
pub const MAX_RESPONSE_SIZE: u64 = 10 * 1024 * 1024;

/// Fetch a single URL and return the response data + discovered links.
///
/// Sends the page body and headers through `page_tx` for the scanner.
/// Returns discovered links for the main loop to add to the frontier.
pub async fn fetch_page(
    client: &reqwest::Client,
    url: Url,
    depth: usize,
    page_tx: &tokio::sync::mpsc::Sender<PageData>,
) -> CrawlResult {
    let response = match client.get(url.as_str()).send().await {
        Ok(r) => r,
        Err(e) => {
            return CrawlResult {
                discovered_urls: vec![],
                bytes_downloaded: 0,
                error: Some(format!("Request failed: {e}")),
            };
        }
    };

    let status = response.status().as_u16();
    let headers = response.headers().clone();

    // Enforce size limit
    if let Some(len) = response.content_length()
        && len > MAX_RESPONSE_SIZE
    {
        return CrawlResult {
            discovered_urls: vec![],
            bytes_downloaded: 0,
            error: Some(format!("Response too large: {len} bytes")),
        };
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return CrawlResult {
                discovered_urls: vec![],
                bytes_downloaded: 0,
                error: Some(format!("Failed to read body: {e}")),
            };
        }
    };

    let bytes_downloaded = body.len();

    // Send page data to scanner (non-blocking best-effort)
    let _ = page_tx
        .send(PageData {
            url: url.to_string(),
            body: body.clone(),
            headers,
            status,
        })
        .await;

    // Extract links only from HTML responses
    let discovered_urls = if content_type.contains("text/html") {
        extract_links(&body, &url, depth + 1)
    } else {
        vec![]
    };

    CrawlResult {
        discovered_urls,
        bytes_downloaded,
        error: None,
    }
}

/// Parse an HTML document and extract all `<a href="...">` links.
///
/// Resolves relative URLs against `base_url`. Filters out non-HTTP schemes
/// and common non-navigable prefixes (javascript:, mailto:, tel:).
pub fn extract_links(html: &str, base_url: &Url, next_depth: usize) -> Vec<(Url, usize)> {
    let document = Html::parse_document(html);
    let Ok(selector) = Selector::parse("a[href]") else {
        return vec![];
    };

    let mut links = Vec::new();

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            let href = href.trim();

            if href.is_empty()
                || href.starts_with("javascript:")
                || href.starts_with("mailto:")
                || href.starts_with("tel:")
                || href.starts_with('#')
                || href.starts_with("data:")
            {
                continue;
            }

            if let Ok(resolved) = base_url.join(href) {
                match resolved.scheme() {
                    "http" | "https" => links.push((resolved, next_depth)),
                    _ => {}
                }
            }
        }
    }

    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_absolute_links() {
        let html = r#"<html><body>
            <a href="https://example.com/page1">Page 1</a>
            <a href="https://example.com/page2">Page 2</a>
        </body></html>"#;

        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links(html, &base, 1);

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].0.as_str(), "https://example.com/page1");
        assert_eq!(links[1].0.as_str(), "https://example.com/page2");
        assert_eq!(links[0].1, 1);
    }

    #[test]
    fn test_extract_relative_links() {
        let html = r#"<a href="/about">About</a><a href="contact">Contact</a>"#;
        let base = Url::parse("https://example.com/pages/").unwrap();
        let links = extract_links(html, &base, 2);

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].0.as_str(), "https://example.com/about");
        assert_eq!(links[1].0.as_str(), "https://example.com/pages/contact");
    }

    #[test]
    fn test_filters_javascript_and_mailto() {
        let html = r##"
            <a href="javascript:void(0)">JS</a>
            <a href="mailto:test@example.com">Email</a>
            <a href="tel:+1234567890">Phone</a>
            <a href="#section">Anchor</a>
            <a href="data:text/html,hello">Data</a>
            <a href="/real-page">Real</a>
        "##;
        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links(html, &base, 1);

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].0.as_str(), "https://example.com/real-page");
    }

    #[test]
    fn test_filters_non_http_schemes() {
        let html = r#"<a href="ftp://files.example.com/data">FTP</a>
                       <a href="https://example.com/ok">OK</a>"#;
        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links(html, &base, 1);

        assert_eq!(links.len(), 1);
    }

    #[test]
    fn test_empty_html() {
        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links("", &base, 1);
        assert!(links.is_empty());
    }

    #[test]
    fn test_no_href_attribute() {
        let html = r#"<a name="anchor">No href</a>"#;
        let base = Url::parse("https://example.com").unwrap();
        let links = extract_links(html, &base, 1);
        assert!(links.is_empty());
    }
}
