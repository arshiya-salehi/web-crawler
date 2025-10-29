import re
from urllib.parse import urlparse

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    #
    # Keep logic inside this function without changing function signature.
    from urllib.parse import urljoin, urldefrag

    out = []
    try:
        if resp is None or resp.status != 200:
            return out
        raw = getattr(resp, "raw_response", None)
        if raw is None:
            return out

        base_url = getattr(raw, "url", None) or getattr(resp, "url", url) or url
        content_bytes = getattr(raw, "content", b"") or b""
        if not content_bytes:
            return out

        # Only handle HTML-like responses
        headers = getattr(raw, "headers", {}) or {}
        ctype = headers.get("Content-Type") or headers.get("content-type")
        if ctype and ("text/html" not in ctype and "application/xhtml" not in ctype):
            return out

        # Decode safely
        try:
            html = content_bytes.decode("utf-8", errors="ignore")
        except Exception:
            try:
                html = content_bytes.decode("latin-1", errors="ignore")
            except Exception:
                return out

        # Extract links with a simple regex fallback (no external deps)
        hrefs = re.findall(r"href\s*=\s*['\"]([^'\"]+)['\"]", html, flags=re.IGNORECASE)

        seen = set()
        for href in hrefs:
            if not href:
                continue
            href = href.strip()
            low = href.lower()
            if low.startswith("javascript:") or low.startswith("mailto:"):
                continue
            abs_url = urljoin(base_url, href)
            abs_url, _ = urldefrag(abs_url)
            if abs_url in seen:
                continue
            seen.add(abs_url)
            out.append(abs_url)
    except Exception:
        # Be safe: return what we have if any
        return out

    return out

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        from urllib.parse import parse_qs

        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        # Keep original file-type blacklist behavior
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()):
            return False

        # Restrict to allowed domains
        host = parsed.hostname or ""
        allowed_suffixes = (".ics.uci.edu", ".cs.uci.edu", ".informatics.uci.edu", ".stat.uci.edu")
        if not any(host.endswith(suf) for suf in allowed_suffixes):
            return False

        # Basic trap avoidance
        if len(url) > 200:
            return False
        if len(parse_qs(parsed.query, keep_blank_values=True)) > 5:
            return False
        if re.search(r"(/.+)\1{2,}", parsed.path):
            return False
        lower = (parsed.path + "?" + parsed.query).lower()
        for kw in ("calendar", "ical", "wp-json", "filter", "sort", "format=", "replytocom", "share=", "feed", "rss"):
            if kw in lower:
                return False

        return True

    except TypeError:
        print ("TypeError for ", parsed)
        raise