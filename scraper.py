import re
from urllib.parse import urlparse, urljoin, urldefrag
from collections import Counter, defaultdict
from bs4 import BeautifulSoup

# --------------------
# Simple analytics state (module-level)
# --------------------
_seen_pages = set()  # defragmented URLs seen (uniqueness by URL without fragment)
_word_freq = Counter()
_longest_page = {"url": None, "word_count": 0}
_subdomain_to_pages = defaultdict(set)  # subdomain (within uci.edu) -> set(urls)

# Lightweight similarity tracking (simhash)
_seen_simhashes = []  # list[int]

# Basic English stopwords (static to avoid external downloads)
_STOPWORDS = {
    "a","about","above","after","again","against","all","am","an","and","any","are","aren't","as",
    "at","be","because","been","before","being","below","between","both","but","by","can't","cannot",
    "could","couldn't","did","didn't","do","does","doesn't","doing","don't","down","during","each","few",
    "for","from","further","had","hadn't","has","hasn't","have","haven't","having","he","he'd","he'll",
    "he's","her","here","here's","hers","herself","him","himself","his","how","how's","i","i'd","i'll",
    "i'm","i've","if","in","into","is","isn't","it","it's","its","itself","let's","me","more","most",
    "mustn't","my","myself","no","nor","not","of","off","on","once","only","or","other","ought","our",
    "ours","ourselves","out","over","own","same","shan't","she","she'd","she'll","she's","should","shouldn't",
    "so","some","such","than","that","that's","the","their","theirs","them","themselves","then","there",
    "there's","these","they","they'd","they'll","they're","they've","this","those","through","to","too","under",
    "until","up","very","was","wasn't","we","we'd","we'll","we're","we've","were","weren't","what","what's",
    "when","when's","where","where's","which","while","who","who's","whom","why","why's","with","won't","would",
    "wouldn't","you","you'd","you'll","you're","you've","your","yours","yourself","yourselves"
}

# Allowed host patterns
_ALLOWED_HOST_ENDINGS = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
)

# Disallowed path keywords/traps (heuristic)
_TRAP_KEYWORDS = (
    "calendar", "ical", "wp-json", "wp-login", "login", "logout", "signup", "register",
    "share", "print", "format=pdf", "attachment", "replytocom", "sort=", "session",
    "sid=", "phpsessid", "preview", "?replytocom=", "action=", "rss", "feed", "?page=",
)

# File extensions to skip (expanded)
_SKIP_EXTENSIONS = (
    "css","js","bmp","gif","jpe","jpeg","jpg","ico","png","tiff","tif","mid","mp2","mp3","mp4",
    "wav","avi","mov","mpeg","ram","m4v","mkv","ogg","ogv","pdf","ps","eps","tex","ppt","pptx","doc",
    "docx","xls","xlsx","names","data","dat","exe","bz2","tar","msi","bin","7z","psd","dmg","iso","epub",
    "dll","cnf","tgz","sha1","thmx","mso","arff","rtf","jar","csv","rm","smil","wmv","swf","wma","zip",
    "rar","gz","svg","webp","heic","heif","apk","m4a","aac","flac","webm","ts","m3u8","map","avi",
    "xml","json","txt","md","war"
)

# Size limits and thresholds
_MAX_BYTES = 2 * 1024 * 1024  # 2MB cap to avoid very large files of low value
_MIN_TEXT_WORDS = 50          # below this, likely low-information
_MIN_UNIQUE_RATIO = 0.2       # unique/total words ratio threshold
_SIMHASH_HAMMING_MAX = 3      # near-duplicate tolerance (64-bit simhash)


def _defragment(url: str) -> str:
    clean, _ = urldefrag(url)
    return clean


def _is_allowed_domain(netloc: str) -> bool:
    netloc = netloc.lower()
    return (
        netloc.endswith(_ALLOWED_HOST_ENDINGS)
        or netloc == "ics.uci.edu"
        or netloc == "cs.uci.edu"
        or netloc == "informatics.uci.edu"
        or netloc == "stat.uci.edu"
    )


def _simhash(tokens):
    # Simple 64-bit simhash over tokens
    if not tokens:
        return 0
    v = [0] * 64
    for t in tokens:
        h = hash(t)
        # normalize Python hash to stable 64-bit across run (best-effort)
        x = h & ((1 << 64) - 1)
        for i in range(64):
            bit = 1 if (x >> i) & 1 else 0
            v[i] += 1 if bit else -1
    fp = 0
    for i in range(64):
        if v[i] >= 0:
            fp |= (1 << i)
    return fp


def _hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


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
    try:
        if resp is None or resp.status != 200 or resp.raw_response is None:
            return []

        # Content-Type and Content-Length gates
        content_type = resp.raw_response.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            return []
        try:
            clen = int(resp.raw_response.headers.get("Content-Length", "0"))
        except Exception:
            clen = 0
        if clen and clen > _MAX_BYTES:
            return []

        actual_url = resp.url or url
        actual_url = _defragment(actual_url)
        parsed = urlparse(actual_url)
        if parsed.scheme not in {"http", "https"}:
            return []

        html_bytes = resp.raw_response.content or b""
        if not html_bytes:
            # Dead 200: no content
            return []
        if not clen and len(html_bytes) > _MAX_BYTES:
            return []

        soup = BeautifulSoup(html_bytes, "html.parser")

        # Extract text for analytics, excluding scripts/styles
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
        words = re.findall(r"[a-zA-Z]+", text.lower())
        filtered_words = [w for w in words if w not in _STOPWORDS and len(w) > 1]

        # Low information page filter
        total = len(filtered_words)
        unique = len(set(filtered_words)) if total else 0
        unique_ratio = (unique / total) if total else 0.0
        if total < _MIN_TEXT_WORDS or unique_ratio < _MIN_UNIQUE_RATIO:
            return []

        # Near-duplicate detection via simhash
        fp = _simhash(filtered_words[:5000])  # cap tokens for speed
        for seen_fp in _seen_simhashes:
            if _hamming(fp, seen_fp) <= _SIMHASH_HAMMING_MAX:
                return []
        _seen_simhashes.append(fp)

        # Update analytics (uniques by URL, longest page, word freq, subdomains)
        if actual_url not in _seen_pages:
            _seen_pages.add(actual_url)
            _word_freq.update(filtered_words)
            if len(filtered_words) > _longest_page["word_count"]:
                _longest_page["word_count"] = len(filtered_words)
                _longest_page["url"] = actual_url
            netloc = parsed.netloc.lower()
            if netloc.endswith(".uci.edu") or netloc == "uci.edu":
                _subdomain_to_pages[netloc].add(actual_url)

        # Extract and normalize links
        links = []
        for a in soup.find_all("a", href=True):
            href = a.get("href").strip()
            if not href or href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                continue
            abs_url = urljoin(actual_url, href)
            abs_url = _defragment(abs_url)
            links.append(abs_url)

        return links
    except Exception:
        # Be conservative on unexpected parse errors
        return []


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        if not url:
            return False
        url = _defragment(url)
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        # Domain/path constraints
        netloc = parsed.netloc.lower()
        if not _is_allowed_domain(netloc):
            return False

        # Basic trap avoidance
        # 1) Block excessive path length or repeated segments
        path = parsed.path or "/"
        if len(url) > 2000:
            return False
        segments = [seg for seg in path.split("/") if seg]
        if len(segments) > 20:
            return False
        # same segment repeated 3+ times (e.g., /foo/foo/foo)
        seg_counts = Counter(segments)
        if any(c >= 3 for c in seg_counts.values()):
            return False
        # high digit ratio in segments often calendar-like traps
        digits = sum(ch.isdigit() for ch in path)
        if len(path) > 0 and (digits / len(path)) > 0.3:
            return False
        # year/month pattern like /2020/12/
        if re.search(r"/(19|20)\d{2}/(0?[1-9]|1[0-2])(/|$)", path):
            return False

        # 2) Query traps
        query = (parsed.query or "").lower()
        if query.count("&") + (1 if query else 0) > 5:
            return False
        trap_hit = any(k in query for k in _TRAP_KEYWORDS) or any(k in path.lower() for k in _TRAP_KEYWORDS)
        if trap_hit:
            return False
        # suspicious large page=number
        if re.search(r"[?&]page=\d{3,}", query):
            return False

        # 3) Disallow non-HTML resources by extension
        path_lower = parsed.path.lower()
        if re.search(r"\.({})$".format("|".join(map(re.escape, _SKIP_EXTENSIONS))), path_lower):
            return False

        return True

    except TypeError:
        print("TypeError for ", url)
        raise
