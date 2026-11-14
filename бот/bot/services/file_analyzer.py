from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import requests
from aiogram import Bot


def _get_vt_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "")
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{hash}"
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"

MAX_FILE_SIZE = 32 * 1024 * 1024

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jse", ".wsf", ".hta", ".msi", ".jar", ".ps1", ".lnk",
}

DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|js|vbs)$", re.I)


@dataclass
class FileSignal:
    id: str
    score: float
    reason: str


@dataclass
class FileAnalysisResult:
    filename: str
    size: int
    sha256: str
    score: float
    verdict: str
    signals: list[FileSignal] = field(default_factory=list)
    vt_stats: dict | None = None
    known_malware: bool = False

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in ("medium", "high")


def _verdict(score: float) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _aggregate(signals: list[FileSignal]) -> float:
    if not signals:
        return 0.0
    complement = 1.0
    for s in signals:
        complement *= (1.0 - min(1.0, s.score))
    return round((1.0 - complement) * 100, 1)


def _check_extension(filename: str) -> list[FileSignal]:
    signals: list[FileSignal] = []
    name = filename.lower()

    if DOUBLE_EXT_RE.search(name):
        signals.append(FileSignal(
            "double_extension", 0.9,
            f"Двойное расширение — файл маскируется под документ ({filename})",
        ))
        return signals

    ext = Path(name).suffix
    if ext in SUSPICIOUS_EXTENSIONS:
        signals.append(FileSignal(
            "suspicious_extension", 0.7,
            f"Исполняемый или скриптовый файл ({ext}) — может запустить код",
        ))
    return signals


def _check_virustotal_hash(sha256: str, timeout: int = 10) -> tuple[list[FileSignal], dict | None]:
    api_key = _get_vt_key()
    if not api_key:
        return [], None

    try:
        resp = requests.get(
            VT_FILE_URL.format(hash=sha256),
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return [], None

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        signals: list[FileSignal] = []
        if malicious > 0:
            signals.append(FileSignal(
                "vt_malicious", min(malicious / 10, 1.0),
                f"VirusTotal: {malicious} движков считают файл вредоносным",
            ))
        if suspicious > 0:
            signals.append(FileSignal(
                "vt_suspicious", min(suspicious / 15, 0.7),
                f"VirusTotal: {suspicious} движков считают файл подозрительным",
            ))
        return signals, stats
    except Exception:
        return [], None

def _check_malwarebazaar(sha256: str, timeout: int = 10) -> tuple[list[FileSignal], bool]:
    try:
        resp = requests.post(
            MB_API_URL,
            data={"query": "get_info", "hash": sha256},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return [], False

        data = resp.json()
        if data.get("query_status") != "ok":
            return [], False

        return [FileSignal(
            "mb_known", 1.0,
            "MalwareBazaar (abuse.ch): файл известен как вредоносный образец",
        )], True
    except Exception:
        return [], False


def _cleanup(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


async def analyze_document(
    bot: Bot,
    file_id: str,
    filename: str | None,
    file_size: int | None,
) -> FileAnalysisResult:

    safe_name = filename or "file"
    sha256 = ""
    tmp_path = ""

    try:
        if file_size and file_size > MAX_FILE_SIZE:
            return FileAnalysisResult(
                filename=safe_name, size=file_size, sha256="",
                score=0.0, verdict="low",
                signals=[FileSignal(
                    "too_large", 0.0,
                    f"Файл больше {MAX_FILE_SIZE // (1024*1024)} МБ — "
                    "проверка по хэшу без загрузки недоступна",
                )],
            )

        tg_file = await bot.get_file(file_id)
        fd, tmp_path = tempfile.mkstemp(suffix=Path(safe_name).suffix or ".bin")
        os.close(fd)
        await bot.download_file(tg_file.file_path, destination=tmp_path)

        h = hashlib.sha256()
        with open(tmp_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        sha256 = h.hexdigest()

        signals: list[FileSignal] = []
        signals.extend(_check_extension(safe_name))

        vt_signals, vt_stats = _check_virustotal_hash(sha256)
        signals.extend(vt_signals)

        mb_signals, known = _check_malwarebazaar(sha256)
        signals.extend(mb_signals)

        if not vt_signals and not mb_signals:
            signals.append(FileSignal(
                "unknown", 0.15,
                "Файл неизвестен базам VirusTotal и MalwareBazaar — "
                "проверьте вручную, если сомневаетесь в отправителе",
            ))

        signals.sort(key=lambda s: s.score, reverse=True)
        score = _aggregate(signals)

        return FileAnalysisResult(
            filename=safe_name,
            size=file_size or os.path.getsize(tmp_path),
            sha256=sha256,
            score=score,
            verdict=_verdict(score),
            signals=signals,
            vt_stats=vt_stats,
            known_malware=known,
        )
    finally:
        if tmp_path:
            _cleanup(tmp_path)
