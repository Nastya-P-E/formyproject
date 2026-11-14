import asyncio
from html import escape

from aiogram import Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import Message

from bot.services.text_analyzer import analyze_text
from bot.services.url_analyzer import analyze_url, extract_urls
from bot.services.file_analyzer import analyze_document, MAX_FILE_SIZE


router = Router(name="text_handler")

VERDICT_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴", "unchecked": "⚪"}
VERDICT_LABEL = {"low": "Низкий риск", "medium": "Средний риск", "high": "Высокий риск", "unchecked": "Безопасность не определена"}


class ScanStates(StatesGroup):
    waiting_for_message = State()
    waiting_for_link = State()
    waiting_for_document = State()


def _format_response(text: str) -> str:
    result = analyze_text(text)
    lines = [
        f"{VERDICT_EMOJI[result.verdict]} <b>{VERDICT_LABEL[result.verdict]}</b> — "
        f"оценка подозрительности: {result.score}/100",
        "━━━━━━━━━━━━",
    ]
    if not result.signals:
        lines.append("Известных признаков мошенничества не найдено.")
        lines.append("Безопасность сообщения не подтверждена.")
    else:
        lines.append("<b>Найденные признаки:</b>")
        for sig in result.signals[:3]:
            lines.append(f"• {sig.reason}")
        if result.is_suspicious:
            lines.append("")
            lines.append("⚠️ Не переходите по ссылкам и не сообщайте коды/данные карты.")
    return "\n".join(lines)


def _format_url_result(url: str) -> str:
    r = analyze_url(url, use_virustotal=True)
    lines = [
        f"{VERDICT_EMOJI[r.verdict]} <b>{VERDICT_LABEL[r.verdict]}</b> — "
        f"оценка подозрительности: {r.score}/100",
        f"Ссылка: <code>{escape(url[:100])}</code>",
        "━━━━━━━━━━━━",
    ]
    if not r.signals:
        lines.append("Известных признаков не найдено. Безопасность ссылки не подтверждена.")
    else:
        lines.append("<b>Найденные признаки:</b>")
        for sig in r.signals[:3]:
            lines.append(f"• {sig.reason}")
        if r.is_suspicious:
            lines.append("")
            lines.append("⚠️ Не переходите по этой ссылке.")
    statuses = {
        "disabled": "VirusTotal отключён: выполнена только проверка адреса по правилам.",
        "not_configured": "VirusTotal не настроен: отсутствует API-ключ.",
        "private_url": "Локальный адрес не отправлен в VirusTotal.",
        "not_found": "В VirusTotal нет готового отчёта. Адрес на сканирование не отправлялся.",
        "pending": "В VirusTotal пока нет завершённого результата.",
        "error": "VirusTotal недоступен: выполнена только проверка по правилам.",
        "completed": "Учтён ранее созданный отчёт VirusTotal; он может быть устаревшим.",
    }
    lines.append(statuses[r.vt_status])
    return "\n".join(lines)


async def _url_response(url: str) -> str:
    try:
        # Blocking HTTP must not stop the event loop for other messages.
        return await asyncio.to_thread(_format_url_result, url)
    except ValueError as exc:
        return "❌ " + escape(str(exc))


@router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Привет! Я бот, который помогает распознать мошенников.\n\n"
        "Команды:\n"
        "/scanmessage — проверить текст сообщения\n"
        "/scanlink — проверить ссылку\n"
        "/scanfile — проверить документ до 10 МиБ\n"
        "/stop — отменить проверку\n"
        "/help — справка\n\n"
        "Или просто пришли мне текст — я его проверю.",
    )


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "Список команд:\n"
        "/start — запустить бота\n"
        "/scanmessage — проверить сообщение\n"
        "/scanlink — проверить ссылку\n"
        "/scanfile — проверить документ до 10 МиБ\n"
        "/stop — остановить проверку\n"
        "/help — эта справка\n\n"
        "Число 0–100 — внутренняя оценка на основе правил, "
        "а не вероятность мошенничества.\n"
        "Отсутствие совпадений не гарантирует безопасность сообщения.\n"
        "По умолчанию ссылки проверяются локально, без открытия сайтов.\n"
        "Если владелец включил VirusTotal, адрес передаётся этому сервису для поиска готового отчёта.\n"
        "Не присылайте приватные ссылки и ссылки с паролями или кодами доступа.\n"
        "Документы: признаки в имени и SHA-256; файл не запускается. Внешние базы по умолчанию отключены.\n"
        "При включении VirusTotal/MalwareBazaar им передаётся хэш, содержимое не загружается.\n"
        "/stop отменяет ожидание следующего сообщения или файла.",
    )


@router.message(Command("scanmessage"))
async def cmd_scan(message: Message, state: FSMContext):
    await state.set_state(ScanStates.waiting_for_message)
    await message.answer(
        "Пришлите ваше сообщение, пожалуйста.\n(или /stop, чтобы отменить)"
    )


@router.message(Command("scanlink"))
async def cmd_scanlink(message: Message, state: FSMContext):
    await state.set_state(ScanStates.waiting_for_link)
    await message.answer(
        "Пришлите ссылку, которую нужно проверить.\n(или /stop, чтобы отменить)"
    )


@router.message(Command("scanfile"))
async def cmd_scanfile(message: Message, state: FSMContext):
    await state.set_state(ScanStates.waiting_for_document)
    await message.answer("Пришлите документ до 10 МиБ. Файл не запускается. /stop — отменить ожидание.")


@router.message(Command("stop"))
async def cmd_stop(message: Message, state: FSMContext):
    current = await state.get_state()
    await state.clear()
    if current in (
        ScanStates.waiting_for_message.state,
        ScanStates.waiting_for_link.state,
        ScanStates.waiting_for_document.state,
    ):
        await message.answer("⏹ Проверка остановлена.")
    else:
        await message.answer("Нечего останавливать — проверка не запущена.")


@router.message(F.text.startswith("/"))
async def unknown_command(message: Message):
    cmd = message.text.split()[0]
    await message.answer(
        f"❌ Некорректная команда: <code>{escape(cmd)}</code>\n\n"
        "Доступные команды:\n"
        "/start, /scanmessage, /scanlink, /scanfile, /stop, /help",
        parse_mode="HTML",
    )


_FILE_SLOTS = None
_FILE_LOOP = None


def _document_slots():
    # Python 3.9 binds Semaphore to the loop at construction time.
    global _FILE_SLOTS, _FILE_LOOP
    loop = asyncio.get_running_loop()
    if _FILE_LOOP is not loop:
        _FILE_SLOTS = asyncio.Semaphore(2)
        _FILE_LOOP = loop
    return _FILE_SLOTS


def _format_file_result(result):
    lines = [f"{VERDICT_EMOJI[result.verdict]} <b>{VERDICT_LABEL[result.verdict]}</b>",
             f"Файл: <code>{escape(result.filename)}</code>"]
    if result.score is not None:
        lines.append(f"Оценка признаков: {result.score}/100 (не вероятность)")
    if result.sha256:
        lines.append(f"SHA-256: <code>{result.sha256}</code>")
    for signal in result.signals[:3]:
        lines.append("• " + escape(signal.reason))
    statuses = {"disabled": "отключён", "not_configured": "нет API-ключа",
                "not_found": "хэш не найден", "pending": "нет готового результата",
                "completed": "готовый отчёт получен", "error": "сервис недоступен или вернул ошибку"}
    lines.append("VirusTotal: " + statuses[result.vt_status])
    lines.append("MalwareBazaar: " + statuses[result.mb_status])
    lines.append(escape(result.note))
    if result.is_suspicious:
        lines.append("⚠️ Не открывайте файл; проверьте отправителя.")
    return "\n".join(lines)


@router.message(F.document)
async def handle_document(message: Message, state: FSMContext):
    await message.answer("⏳ Проверяю файл. Без внешних ключей доступны только признаки имени и SHA-256.")
    try:
        async with _document_slots():
            result = await analyze_document(message.bot, message.document.file_id,
                                            filename=message.document.file_name,
                                            file_size=message.document.file_size)
        await message.reply(_format_file_result(result), parse_mode="HTML")
        await state.clear()
    except Exception:
        await message.answer("Не удалось проверить файл. Попробуйте позже.")


@router.message(F.text.is_(None))
async def non_text_message(message: Message):
    await message.answer(
        "❌ Некорректный формат сообщения.\n"
        "Пришлите текст, ссылку или файл как документ (до 10 МиБ).\n"
        "Фото и голосовые сообщения пока не анализируются.",
    )


@router.message(F.text)
async def handle_text(message: Message, state: FSMContext):
    text = message.text.strip()
    if not text:
        return

    if len(text) > 4000:
        await message.reply("Сообщение слишком длинное (макс. 4000 симв.).")
        return

    current = await state.get_state()

    if current == ScanStates.waiting_for_document.state:
        await message.answer("Ожидаю документ до 10 МиБ. /stop — отменить ожидание.")
        return

    if current == ScanStates.waiting_for_link.state:
        reply = await _url_response(text)
        await message.reply(reply, parse_mode="HTML", disable_web_page_preview=True)
        await state.clear()
        return

    reply = _format_response(text)

    urls = extract_urls(text)
    for u in urls[:3]:
        reply += "\n\n" + await _url_response(u)

    await message.reply(reply, parse_mode="HTML", disable_web_page_preview=True)

    if current == ScanStates.waiting_for_message.state:
        await state.clear()
