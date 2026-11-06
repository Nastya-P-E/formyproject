from __future__ import annotations

import re
from dataclasses import dataclass, field

from rapidfuzz import fuzz

from .scam_patterns import TEMPLATES, REGEX_RULES, ScamTemplate


FUZZY_MIN_RATIO = 55.0

FUZZY_WEIGHT = 0.7
REGEX_WEIGHT = 1.0


@dataclass
class Signal:
    source: str
    id: str
    category: str
    weight: float
    score: float
    reason: str


@dataclass
class AnalysisResult:
    score: float
    verdict: str
    signals: list[Signal] = field(default_factory=list)
    matched_template_ids: list[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in ("medium", "high")


_WS_RE = re.compile(r"\s+")
_NON_WORD_RE = re.compile(r"[^\w\s]", re.UNICODE)


def normalize(text: str) -> str:
    if not text:
        return ""
    text = text.lower()
    text = text.replace("ё", "е")
    text = _NON_WORD_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    return text

def _match_templates(norm_text: str) -> list[Signal]:
    signals: list[Signal] = []
    for tpl in TEMPLATES:
        norm_tpl = normalize(tpl.text)
        if not norm_tpl:
            continue

        ratio = fuzz.token_set_ratio(norm_text, norm_tpl)
        if ratio < FUZZY_MIN_RATIO:
            continue

        keyword_hits = sum(1 for kw in tpl.keywords if kw in norm_text)
        keyword_bonus = min(keyword_hits, len(tpl.keywords)) / max(len(tpl.keywords), 1)

        confidence = (ratio / 100.0) * 0.7 + keyword_bonus * 0.3
        confidence = max(0.0, min(confidence, 1.0))

        score = tpl.weight * confidence

        if score < 0.25:
            continue

        reason = (
            f"Похоже на шаблон «{tpl.category}» "
            f"(сходство {ratio:.0f}%, ключевых слов {keyword_hits}/{len(tpl.keywords)})"
        )
        signals.append(
            Signal(
                source="template",
                id=tpl.id,
                category=tpl.category,
                weight=tpl.weight,
                score=score,
                reason=reason,
            )
        )
    return signals


def _match_regex(text: str) -> list[Signal]:
    signals: list[Signal] = []
    for rule_id, category, weight, pattern, description in REGEX_RULES:
        if pattern.search(text):
            signals.append(
                Signal(
                    source="regex",
                    id=rule_id,
                    category=category,
                    weight=weight,
                    score=weight,
                    reason=description,
                )
            )
    return signals

def _aggregate(signals: list[Signal]) -> float:
    if not signals:
        return 0.0

    complement = 1.0
    for s in signals:
        w = FUZZY_WEIGHT if s.source == "template" else REGEX_WEIGHT
        contrib = min(1.0, s.score * w)
        complement *= (1.0 - contrib)

    return round((1.0 - complement) * 100, 1)


def _verdict(score: float) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"



def analyze_text(text: str) -> AnalysisResult:
    if not text or not text.strip():
        return AnalysisResult(score=0.0, verdict="low")

    norm = normalize(text)

    signals = _match_regex(text) + _match_templates(norm)
    signals.sort(key=lambda s: s.score, reverse=True)

    score = _aggregate(signals)
    verdict = _verdict(score)

    matched_ids = [s.id for s in signals if s.source == "template"]

    return AnalysisResult(
        score=score,
        verdict=verdict,
        signals=signals,
        matched_template_ids=matched_ids,
    )