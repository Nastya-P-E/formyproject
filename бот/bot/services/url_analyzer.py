from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import tldextract
import requests


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
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

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in ("medium", "high")

def _extract_parts(url: str):
    """Возвращает (scheme, host, path, registered_domain, subdomain, tld)."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(parsed.netloc)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return (
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        registered,
        ext.subdomain,
        ext.suffix,
    )

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

    host_no_port = host.split(":")[0]
    if _IP_RE.match(host_no_port):
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

def _check_virustotal(url: str, timeout: int = 10) -> tuple[list[UrlSignal], dict | None]:
    """Возвращает сигналы VT и сырую статистику (или None, если ключа нет/ошибка)."""
    if not VIRUSTOTAL_API_KEY:
        return [], None

    try:
        resp = requests.post(
            VT_URL,
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            data={"url": url},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return [], None

        analysis_id = resp.json()["data"]["id"]
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=timeout,
        )
        if report.status_code != 200:
            return [], None

        stats = report.json()["data"]["attributes"].get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        signals: list[UrlSignal] = []
        if malicious > 0:
            signals.append(UrlSignal(
                "vt_malicious", min(malicious / 10, 1.0),
                f"VirusTotal: {malicious} движков считают ссылку вредоносной",
            ))
        if suspicious > 0:
            signals.append(UrlSignal(
                "vt_suspicious", min(suspicious / 15, 0.7),
                f"VirusTotal: {suspicious} движков считают ссылку подозрительной",
            ))

        return signals, stats
    except Exception:
        return [], None


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
    url = url.strip()
    if not url:
        return UrlAnalysisResult(url="", score=0.0, verdict="low")

    signals = _check_local(url)

    vt_stats = None
    if use_virustotal:
        vt_signals, vt_stats = _check_virustotal(url)
        signals.extend(vt_signals)

    signals.sort(key=lambda s: s.score, reverse=True)
    score = _aggregate(signals)
    return UrlAnalysisResult(
        url=url,
        score=score,
        verdict=_verdict(score),
        signals=signals,
        vt_stats=vt_stats,
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