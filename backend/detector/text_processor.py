"""
ScamShield - Text Processing & Link Analysis Engine
Provides normalization, contextual phrase matching, and deep URL inspection.
"""

import re
import ipaddress
from urllib.parse import urlparse
from .patterns import (
    URL_SHORTENERS,
    SUSPICIOUS_TLDS,
    BENIGN_ADVISORY_PATTERNS,
    OTP_REQUEST_PATTERNS,
)


class TextProcessor:
    """Helper utility for text sanitization, pattern extraction, and link analysis."""

    # Match http/https URLs, www URLs, and domain patterns
    URL_REGEX = re.compile(
        r'(?:https?://[^\s<>"]+|www\.[^\s<>"]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|buzz|club|online|site|app|co|in|info|biz|io|cc|ly|to)(?:/[^\s<>"]*)?)',
        re.IGNORECASE,
    )

    @staticmethod
    def normalize(text: str) -> str:
        if not text:
            return ""
        normalized = text.lower()
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized

    @classmethod
    def extract_urls(cls, text: str) -> list:
        raw_matches = cls.URL_REGEX.findall(text)
        analyzed_links = []
        seen = set()

        for raw in raw_matches:
            clean_url = raw.rstrip('.,;!?):"\'')
            if clean_url in seen or len(clean_url) < 4:
                continue
            seen.add(clean_url)

            parseable_url = clean_url
            if not parseable_url.startswith(("http://", "https://")):
                parseable_url = "http://" + parseable_url

            parsed = urlparse(parseable_url)
            hostname = (parsed.hostname or "").lower()
            scheme = parsed.scheme.lower()

            is_shortened = any(shortener in hostname for shortener in URL_SHORTENERS)
            is_ip = False
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                is_ip = False

            has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)

            subdomain_parts = [p for p in hostname.split(".") if p]
            excessive_subdomains = len(subdomain_parts) >= 4 and not is_ip

            notes = []
            if is_shortened:
                notes.append(
                    "URL shortening obscures the actual destination and makes verification difficult. "
                    "This is frequently used in phishing campaigns."
                )
            if is_ip:
                notes.append(
                    "The link uses a raw numerical IP address instead of a registered domain name, "
                    "which is strongly associated with phishing infrastructure."
                )
            if has_suspicious_tld:
                notes.append(
                    f"The link uses a high-risk top-level domain ({subdomain_parts[-1] if subdomain_parts else 'domain'}), "
                    "often leveraged by bulk automated spam tools."
                )
            if excessive_subdomains:
                notes.append(
                    "Excessive subdomains detected. Phishing pages often mimic legitimate brand names "
                    "inside subdomains (e.g., sbi.bank.login.phishingsite.com)."
                )

            if scheme == "http":
                notes.append(
                    "Connection is unencrypted (HTTP). Legitimate services handle accounts and payments over HTTPS."
                )
            elif scheme == "https":
                notes.append(
                    "Connection is encrypted (HTTPS). Note: HTTPS only secures data in transit and does NOT "
                    "guarantee that the website is trustworthy or legitimate."
                )

            is_suspicious = is_shortened or is_ip or has_suspicious_tld or excessive_subdomains

            analyzed_links.append({
                "raw_url": clean_url,
                "hostname": hostname,
                "scheme": scheme,
                "is_shortened": is_shortened,
                "is_ip": is_ip,
                "has_suspicious_tld": has_suspicious_tld,
                "excessive_subdomains": excessive_subdomains,
                "is_suspicious": is_suspicious,
                "notes": notes,
            })

        return analyzed_links

    @classmethod
    def match_phrases(cls, normalized_text: str, patterns: list) -> list:
        matches = []
        for phrase in patterns:
            pattern_regex = r'(?:\b|_)' + re.escape(phrase) + r'(?:\b|_)'
            if re.search(pattern_regex, normalized_text):
                matches.append(phrase)
        return matches

    @classmethod
    def has_benign_advisory(cls, normalized_text: str) -> bool:
        for pattern in BENIGN_ADVISORY_PATTERNS:
            if pattern in normalized_text:
                return True
        return False

    @classmethod
    def is_predatory_otp_request(cls, normalized_text: str) -> bool:
        if cls.has_benign_advisory(normalized_text):
            return False

        for phrase in OTP_REQUEST_PATTERNS:
            if phrase in normalized_text:
                return True

        return False
