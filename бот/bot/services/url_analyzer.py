from __future__ import annotations

import os
import ipaddress
import base64
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract
import requests


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
VT_URL = "https://www.virustotal.com/api/v3/urls"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "is.gd", "t.co",
    "cutt.ly", "rb.gy", "shorturl.at", "clck.ru", "vk.cc",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",   # бесплатные
    "xyz", "top", "club", "online", "site", "icu", "buzz",
}

PHISHING_KEYWORDS = (
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "bank", "wallet", "bonus", "prize",
    "free", "gift", "password", "sms", "code",
)

POPULAR_BRANDS = ("google", "apple", "microsoft", "telegram", "sberbank", "vtb")

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MANY_HYPHENS_RE = re.compile(r"-{2,}")

@dataclass
class UrlSignal:
    id: str
    score: float
    reason: str


@dataclass
class UrlAnalysisResult:
    url: str
    score: float
    verdict: str
    signals: list[UrlSignal] = field(default_factory=list)
    vt_stats: dict | None = None
    vt_status: str = "disabled"

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in ("medium", "high")

def validate_url(url: str) -> str:
    """Accept only a single public HTTP(S) address; never visit the address."""
    url = url.strip()
    if not url or any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError("Пришлите одну ссылку без пробелов.")
    if any(c in url for c in '<>\"'):
        raise ValueError("В ссылке есть недопустимые символы.")
    if "://" not in url:
        url = "https://" + url
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        _ = parsed.port  # Validate the port even though no connection is made.
        if parsed.scheme.lower() not in ("http", "https") or not host:
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii")
            labels = ascii_host.rstrip(".").split(".")
            if len(labels) < 2 or len(ascii_host) > 253 or any(
                not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in labels
            ):
                raise ValueError()
        return url
    except (ValueError, UnicodeError):
        raise ValueError("Некорректная ссылка. Пришлите адрес вида https://example.com.") from None


def _extract_parts(url: str):
    parsed = urlparse(validate_url(url))
    host = parsed.hostname or ""
    ext = _EXTRACT(host)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return parsed.scheme, host, parsed.path, registered, ext.subdomain, ext.suffix


def _check_local(url: str) -> list[UrlSignal]:
    signals: list[UrlSignal] = []
    scheme, host, path, registered, subdomain, tld = _extract_parts(url)
    lower_url = url.lower()
    lower_host = host.lower()

    if registered in SHORTENERS:
        signals.append(UrlSignal(
            "shortener", 0.45,
            f"Сокращённая ссылка ({registered}) — реальный адрес скрыт",
        ))

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        signals.append(UrlSignal(
            "ip_host", 0.6,
            "Ссылка ведёт на IP-адрес, а не на домен",
        ))

    if tld and tld.lower() in SUSPICIOUS_TLDS:
        signals.append(UrlSignal(
            "suspicious_tld", 0.4,
            f"Доменная зона .{tld} часто используется в мошеннических схемах",
        ))

    if "xn--" in lower_host:
        signals.append(UrlSignal(
            "punycode", 0.5,
            "Домен содержит punycode — возможна подмена символов (гомоглифы)",
        ))

    hits = [kw for kw in PHISHING_KEYWORDS if kw in lower_url]
    if hits:
        signals.append(UrlSignal(
            "phishing_keywords", min(0.15 * len(hits), 0.6),
            f"В ссылке есть слова, характерные для фишинга: {', '.join(hits[:3])}",
        ))

    for brand in POPULAR_BRANDS:
        if brand in lower_host and brand not in registered:
            signals.append(UrlSignal(
                "brand_impersonation", 0.55,
                f"Упоминание бренда «{brand}» в чужом домене — возможна подделка",
            ))
            break
        if brand in lower_host and brand != registered.split(".")[0]:
            signals.append(UrlSignal(
                "brand_typo", 0.45,
                f"Домен похож на «{brand}», но не является им",
            ))
            break

    if subdomain and subdomain.count(".") >= 2:
        signals.append(UrlSignal(
            "many_subdomains", 0.3,
            "Слишком много поддоменов — типично для фишинговых страниц",
        ))

    if _MANY_HYPHENS_RE.search(registered):
        signals.append(UrlSignal(
            "many_hyphens", 0.25,
            "В домене несколько дефисов подряд",
        ))

    if scheme == "http":
        signals.append(UrlSignal(
            "no_https", 0.2,
            "Соединение без HTTPS — данные могут передаваться открыто",
        ))

    if len(url) > 120:
        signals.append(UrlSignal(
            "long_url", 0.2,
            "Слишком длинная ссылка — часто маскирует настоящий адрес",
        ))

    return signals

def _check_virustotal(url: str, timeout: int = 5) -> tuple[list[UrlSignal], dict | None, str]:
    """Read an existing report only; do not submit URLs for a new scan."""
    if os.getenv("VIRUSTOTAL_ENABLED", "").lower() != "true":
        return [], None, "disabled"
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return [], None, "not_configured"
    # Avoid sending local/private addresses to an external service.
    host = urlparse(url).hostname or ""
    try:
        if not ipaddress.ip_address(host).is_global:
            return [], None, "private_url"
    except ValueError:
        if host.endswith((".local", ".localhost", ".internal")):
            return [], None, "private_url"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        report = requests.get(
            f"{VT_URL}/{url_id}", headers={"x-apikey": key}, timeout=timeout,
        )
        if report.status_code == 404:
            return [], None, "not_found"
        if report.status_code != 200:
            return [], None, "error"
        attrs = report.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats")
        if not isinstance(stats, dict) or not stats or not any(stats.values()):
            return [], None, "pending"
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        signals = []
        if malicious > 0:
            signals.append(UrlSignal("vt_malicious", max(0.6, min(malicious / 10, 1.0)),
                                    f"VirusTotal: {malicious} движков считают ссылку вредоносной"))
        if suspicious > 0:
            signals.append(UrlSignal("vt_suspicious", max(0.3, min(suspicious / 15, 0.7)),
                                    f"VirusTotal: {suspicious} движков считают ссылку подозрительной"))
        return signals, stats, "completed"
    except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError):
        return [], None, "error"


def _aggregate(signals: list[UrlSignal]) -> float:
    if not signals:
        return 0.0
    complement = 1.0
    for s in signals:
        complement *= (1.0 - min(1.0, s.score))
    return round((1.0 - complement) * 100, 1)


def _verdict(score: float) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"

def analyze_url(url: str, use_virustotal: bool = True) -> UrlAnalysisResult:
    url = validate_url(url)

    signals = _check_local(url)

    vt_stats = None
    vt_status = "disabled"
    if use_virustotal:
        vt_signals, vt_stats, vt_status = _check_virustotal(url)
        signals.extend(vt_signals)

    signals.sort(key=lambda s: s.score, reverse=True)
    score = _aggregate(signals)
    return UrlAnalysisResult(
        url=url,
        score=score,
        verdict=_verdict(score),
        signals=signals,
        vt_stats=vt_stats,
        vt_status=vt_status,
    )


def extract_urls(text: str) -> list[str]:
    pattern = re.compile(
        r"(?:https?://|www\.)[^\s<>\"']+",
        re.IGNORECASE,
    )
    found = pattern.findall(text or "")
    cleaned = []
    for u in found:
        u = u.rstrip(".,;:!?)]}>")
        if u not in cleaned:
            cleaned.append(u)
    return cleaned