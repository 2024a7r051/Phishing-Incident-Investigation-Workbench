"""
URL Analyzer:
1. Extracts all hyperlinks from email text and HTML.
2. Identifies anchor text vs destination URL discrepancies (classic credential harvester trick).
3. Parses domain names and flags IP-based hosts or suspicious schemes.
"""
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, Any, List
from ..utils.defang import defang_url

class URLAnalyzer:
    def __init__(self, text_content: str = "", html_content: str = ""):
        self.text_content = text_content or ""
        self.html_content = html_content or ""

    def analyze(self) -> List[Dict[str, Any]]:
        extracted = []
        seen = set()

        # 1. Parse HTML anchors for href vs text mismatches
        if self.html_content:
            soup = BeautifulSoup(self.html_content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                display_text = a_tag.get_text(strip=True)
                if not href or href.startswith("mailto:") or href.startswith("javascript:"):
                    continue

                mismatch = self._check_href_text_mismatch(href, display_text)
                parsed = urlparse(href)

                if href not in seen:
                    seen.add(href)
                    extracted.append({
                        "url": href,
                        "defanged": defang_url(href),
                        "domain": parsed.netloc or "",
                        "display_text": display_text,
                        "mismatch": mismatch,
                        "is_ip_host": bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}', parsed.netloc)),
                        "scheme": parsed.scheme,
                    })

        # 2. Extract plain text URLs via regex across both plain text and HTML text
        combined_text = self.text_content
        if self.html_content:
            soup = BeautifulSoup(self.html_content, "html.parser")
            combined_text += " " + soup.get_text(separator=" ")

        url_regex = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        for match in url_regex.findall(combined_text):
            url = match.strip('.,;()[]{}')
            if url and url not in seen:
                seen.add(url)
                parsed = urlparse(url if url.startswith("http") else f"http://{url}")
                extracted.append({
                    "url": url,
                    "defanged": defang_url(url),
                    "domain": parsed.netloc or "",
                    "display_text": url,
                    "mismatch": False,
                    "is_ip_host": bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}', parsed.netloc)),
                    "scheme": parsed.scheme,
                })

        return extracted

    def _check_href_text_mismatch(self, href: str, display_text: str) -> bool:
        """Flags cases where text looks like one URL/domain (e.g. paypal.com) but points elsewhere."""
        if not display_text:
            return False

        url_like = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_text)
        if not url_like:
            return False

        claimed_domain = url_like.group(1).lower().replace("www.", "")
        actual_domain = urlparse(href).netloc.lower().replace("www.", "")

        if not actual_domain:
            return False

        if claimed_domain != actual_domain and claimed_domain not in actual_domain:
            return True

        return False
