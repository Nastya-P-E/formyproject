from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import requests
from aiogram import Bot

# Conservative application limit below the hosted Telegram API download limit.
MAX_FILE_SIZE = 10 * 1024 * 1024
VT_FILE_URL = 'https://www.virustotal.com/api/v3/files/{hash}'
MB_API_URL = 'https://mb-api.abuse.ch/api/v1/'
SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
                         '.jse', '.wsf', '.hta', '.msi', '.jar', '.ps1', '.lnk'}
DOUBLE_EXT_RE = re.compile(r'\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|js|vbs)$', re.I)


@dataclass
class FileSignal:
    id: str
    score: float
    reason: str


@dataclass
class FileAnalysisResult:
    filename: str
    size: int
    sha256: str = ''
    score: float | None = None
    verdict: str = 'unchecked'
    signals: list[FileSignal] = field(default_factory=list)
    vt_stats: dict | None = None
    known_malware: bool = False
    vt_status: str = 'disabled'
    mb_status: str = 'disabled'
    note: str = ''

    @property
    def is_suspicious(self) -> bool:
        return self.verdict in ('medium', 'high')


def _check_extension(filename: str) -> list[FileSignal]:
    if DOUBLE_EXT_RE.search(filename):
        return [FileSignal('double_extension', 0.9, 'Двойное расширение: файл может маскироваться под документ')]
    ext = Path(filename.lower()).suffix
    if ext in SUSPICIOUS_EXTENSIONS:
        return [FileSignal('suspicious_extension', 0.7, f'Исполняемый или скриптовый файл ({ext}) — может запустить код')]
    return []


def _check_virustotal_hash(sha256: str) -> tuple[list[FileSignal], dict | None, str]:
    if os.getenv('VIRUSTOTAL_ENABLED', '').lower() != 'true':
        return [], None, 'disabled'
    key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not key:
        return [], None, 'not_configured'
    try:
        response = requests.get(VT_FILE_URL.format(hash=sha256), headers={'x-apikey': key}, timeout=5)
        if response.status_code == 404:
            return [], None, 'not_found'
        if response.status_code != 200:
            return [], None, 'error'
        stats = response.json()['data']['attributes'].get('last_analysis_stats')
        if not isinstance(stats, dict) or not stats or not any(stats.values()):
            return [], None, 'pending'
        malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
        signals = []
        if malicious > 0:
            signals.append(FileSignal('vt_malicious', max(0.6, min(malicious / 10, 1)),
                                      f'VirusTotal: {malicious} движков считают файл вредоносным'))
        if suspicious > 0:
            signals.append(FileSignal('vt_suspicious', max(0.3, min(suspicious / 15, 0.7)),
                                      f'VirusTotal: {suspicious} движков считают файл подозрительным'))
        return signals, stats, 'completed'
    except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError):
        return [], None, 'error'


def _check_malwarebazaar(sha256: str) -> tuple[list[FileSignal], bool, str]:
    if os.getenv('MALWAREBAZAAR_ENABLED', '').lower() != 'true':
        return [], False, 'disabled'
    key = os.getenv('MALWAREBAZAAR_API_KEY', '')
    if not key:
        return [], False, 'not_configured'
    try:
        response = requests.post(MB_API_URL, headers={'Auth-Key': key},
                                 data={'query': 'get_info', 'hash': sha256}, timeout=5)
        if response.status_code != 200:
            return [], False, 'error'
        data = response.json()
        if data.get('query_status') == 'hash_not_found':
            return [], False, 'not_found'
        if data.get('query_status') == 'ok' and data.get('data'):
            return [FileSignal('mb_known', 1, 'MalwareBazaar: файл известен как вредоносный образец')], True, 'completed'
        return [], False, 'error'
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return [], False, 'error'


def _analyze_download(path: str, filename: str, size: int) -> FileAnalysisResult:
    # Runs in a worker thread; cleanup belongs to the worker even if its awaiter is cancelled.
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
        result = FileAnalysisResult(filename=filename, size=size, sha256=h.hexdigest())
        result.signals = _check_extension(filename)
        signals, result.vt_stats, result.vt_status = _check_virustotal_hash(result.sha256)
        result.signals.extend(signals)
        signals, result.known_malware, result.mb_status = _check_malwarebazaar(result.sha256)
        result.signals.extend(signals)
        result.signals.sort(key=lambda signal: signal.score, reverse=True)
        if result.signals or result.vt_status == 'completed':
            complement = 1.0
            for signal in result.signals:
                complement *= 1 - signal.score
            result.score = round((1 - complement) * 100, 1)
            result.verdict = 'high' if result.score >= 60 else ('medium' if result.score >= 30 else 'low')
        result.note = 'Файл не запускался. Отсутствие известных признаков не подтверждает безопасность.'
        return result
    finally:
        Path(path).unlink(missing_ok=True)


class _TooLarge(Exception):
    pass


class _LimitedWriter:
    def __init__(self, stream):
        self.stream, self.size = stream, 0

    def write(self, data):
        if self.size + len(data) > MAX_FILE_SIZE:
            raise _TooLarge()
        self.size += len(data)
        return self.stream.write(data)

    def __getattr__(self, name):
        return getattr(self.stream, name)


async def analyze_document(bot: Bot, file_id: str, filename: str | None,
                           file_size: int | None) -> FileAnalysisResult:
    name = (filename or 'file')[:200]
    result = FileAnalysisResult(filename=name, size=file_size or 0)
    if file_size and file_size > MAX_FILE_SIZE:
        result.note = 'Файл не проверен: лимит бота — 10 МиБ. Пришлите файл меньшего размера.'
        return result
    path = None
    worker_owns_file = False
    try:
        remote = await bot.get_file(file_id)
        if not remote.file_path:
            result.note = 'Не удалось получить файл из Telegram. Попробуйте отправить его ещё раз.'
            return result
        fd, path = tempfile.mkstemp(suffix='.bin')
        with os.fdopen(fd, 'wb') as stream:
            writer = _LimitedWriter(stream)
            await bot.download_file(remote.file_path, destination=writer, timeout=30, seek=False)
        worker_owns_file = True
        return await asyncio.to_thread(_analyze_download, path, name, writer.size)
    except _TooLarge:
        result.note = 'Файл не проверен: фактический размер превышает лимит 10 МиБ.'
        return result
    except Exception:
        # Never echo exceptions: Telegram download URLs may contain the bot token.
        result.note = 'Не удалось проверить файл. Попробуйте позже или пришлите другой документ.'
        return result
    finally:
        if path and not worker_owns_file:
            Path(path).unlink(missing_ok=True)
