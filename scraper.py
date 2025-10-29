import re
import json
import time
from collections import Counter, defaultdict
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# ------------------------------
# Module-level analytics state
# ------------------------------
_analytics_lock = None
try:
    import threading
    _analytics_lock = threading.Lock()
except Exception:
    # Fallback if threading unavailable
    class _NoopLock:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
    _analytics_lock = _NoopLock()

_visited_unique_urls = set()
_subdomain_to_count = defaultdict(int)
_word_counts = Counter()
_longest_page = {"url": None, "word_count": 0}
_last_persist_ts = 0.0

# Minimal English stopword list (extend if desired)
_STOPWORDS = set(
    [
        "the","and","to","of","a","in","for","is","on","that","with","as","by","it","at",
        "from","this","be","are","or","an","we","you","your","our","was","were","will","can",
        "has","have","had","not","but","they","their","he","she","his","her","its","i","me",
        "my","us","about","into","more","most","other","over","such","no","yes","if","there",
        "also","than","then","these","those","within","between","may","all","any","each","per",
        "one","two","three","up","out","new","news","use","used","using","been","which","who",
        "what","when","where","why","how"
    ]
)

_ALLOWED_DOMAINS = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
)

_TRAP_KEYWORDS = (
    "calendar", "ical", "wp-json", "filter", "sort", "format=", "replytocom", "share=",
    "action=login", "session", "token", "download", "feed", "rss", "mailto:", "javascript:"
)

def _persist_analytics_periodically(now: float) -> None:
    global _last_persist_ts
    if now - _last_persist_ts < 15.0:  # write at most every 15 seconds
        return
    data = {
        "unique_url_count": len(_visited_unique_urls),
        "longest_page": _longest_page,
        "top_words": _word_counts.most_common(100),
        "subdomains": dict(sorted(_subdomain_to_count.items())),
    }
    try:
        with open("analytics.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        _last_persist_ts = now
    except Exception:
        # Best-effort persistence; ignore errors
        pass

def scraper(url, resp):
    links = extract_next_links(url, resp)
    filtered = [link for link in links if is_valid(link)]
    return filtered

def extract_next_links(url, resp):
    # url: the URL that was used to get the page
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    out_links = []

    # Fast-fail on non-OK or missing content
    if resp is None or getattr(resp, "status", None) != 200:
        return out_links
    raw = getattr(resp, "raw_response", None)
    if raw is None:
        return out_links

    # Content-type gate: only parse HTML-like content
    content_bytes = getattr(raw, "content", b"") or b""
    if not content_bytes or len(content_bytes) < 32:  # avoid dead/empty pages
        return out_links

    content_type = None
    try:
        headers = getattr(raw, "headers", {}) or {}
        content_type = headers.get("Content-Type") or headers.get("content-type")
    except Exception:
        content_type = None

    if content_type and ("text/html" not in content_type and "application/xhtml" not in content_type):
        return out_links

    # Decode content safely
    html = None
    for enc in ("utf-8", "latin-1"):
        try:
            html = content_bytes.decode(enc, errors="ignore")
            break
        except Exception:
            continue
    if html is None:
        return out_links

    current_url = getattr(raw, "url", None) or getattr(resp, "url", url)

    # Parse and extract text + links
    text_content = ""
    links = []
    if BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "lxml") if "lxml" else BeautifulSoup(html, "html.parser")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")
        # Remove scripts/styles
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text_content = soup.get_text(separator=" ")
        for a in soup.find_all("a", href=True):
            links.append(a.get("href"))
    else:
        # Fallback: very simple link regex
        text_content = re.sub(r"<[^>]+>", " ", html)
        links.extend(re.findall(r"href\s*=\s*['\"]([^'\"]+)['\"]", html, flags=re.IGNORECASE))

    # Tokenize and update analytics
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", text_content)]
    words = [w for w in words if len(w) >= 2 and w not in _STOPWORDS]
    word_count = len(words)

    now = time.time()
    defragmented_current, _ = urldefrag(current_url)
    parsed_current = urlparse(defragmented_current)
    with _analytics_lock:
        _visited_unique_urls.add(defragmented_current)
        # subdomain counting only for *.uci.edu
        if parsed_current.hostname and parsed_current.hostname.endswith(".uci.edu"):
            _subdomain_to_count[parsed_current.hostname] += 1
        _word_counts.update(words)
        if word_count > _longest_page["word_count"]:
            _longest_page["url"] = defragmented_current
            _longest_page["word_count"] = word_count
        _persist_analytics_periodically(now)

    # Resolve, normalize and deduplicate outgoing links
    seen = set()
    for href in links:
        if not href:
            continue
        href = href.strip()
        # Drop javascript/mailto
        if href.lower().startswith("javascript:") or href.lower().startswith("mailto:"):
            continue
        abs_url = urljoin(current_url, href)
        abs_url, _ = urldefrag(abs_url)  # defragment
        if abs_url in seen:
            continue
        seen.add(abs_url)
        out_links.append(abs_url)

    return out_links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        hostname = parsed.hostname or ""

        # Restrict to allowed domains
        allowed = False
        for d in _ALLOWED_DOMAINS:
            if hostname.endswith(d):
                allowed = True
                break
        if not allowed:
            return False

        # Basic filetype exclusions
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            parsed.path.lower(),
        ):
            return False

        # Avoid very long URLs and excessive query parameters
        if len(url) > 200:
            return False
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if len(qs) > 5:
            return False

        # Avoid repeating path segments (trap-like patterns)
        if re.search(r"(/.+)\1{2,}", parsed.path):
            return False

        # Avoid trap keywords in path or query string
        lower_url = (parsed.path + "?" + parsed.query).lower()
        for kw in _TRAP_KEYWORDS:
            if kw in lower_url:
                return False

        return True

    except TypeError:
        print ("TypeError for ", parsed)
        raise