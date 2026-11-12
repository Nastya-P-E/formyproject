from aiogram import Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import Message

from bot.services.text_analyzer import analyze_text
from bot.services.url_analyzer import analyze_url, extract_urls


router = Router(name="text_handler")

VERDICT_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}
VERDICT_LABEL = {"low": "Низкий риск", "medium": "Средний риск", "high": "Высокий риск"}


class ScanStates(StatesGroup):
    waiting_for_message = State()
    waiting_for_link = State()


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
        f"Ссылка: <code>{url[:100]}</code>",
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
    return "\n".join(lines)


@router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Привет! Я бот, который помогает распознать мошенников.\n\n"
        "Команды:\n"
        "/scanmessage — проверить текст сообщения\n"
        "/scanlink — проверить ссылку\n"
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
        "/stop — остановить проверку\n"
        "/help — эта справка\n\n"
        "Число 0–100 — внутренняя оценка на основе правил, "
        "а не вероятность мошенничества.\n"
        "Отсутствие совпадений не гарантирует безопасность сообщения.",
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


@router.message(Command("stop"))
async def cmd_stop(message: Message, state: FSMContext):
    current = await state.get_state()
    await state.clear()
    if current in (
        ScanStates.waiting_for_message.state,
        ScanStates.waiting_for_link.state,
    ):
        await message.answer("⏹ Проверка остановлена.")
    else:
        await message.answer("Нечего останавливать — проверка не запущена.")


@router.message(F.text.startswith("/"))
async def unknown_command(message: Message):
    cmd = message.text.split()[0]
    await message.answer(
        f"❌ Некорректная команда: <code>{cmd}</code>\n\n"
        "Доступные команды:\n"
        "/start, /scanmessage, /scanlink, /stop, /help",
        parse_mode="HTML",
    )


@router.message(F.text.is_(None))
async def non_text_message(message: Message):
    await message.answer(
        "❌ Некорректный формат сообщения.\n"
        "Я умею проверять только текст и ссылки.\n"
        "Пришлите текст сообщения или ссылку.",
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

    if current == ScanStates.waiting_for_link.state:
        reply = _format_url_result(text)
        await message.reply(reply, parse_mode="HTML", disable_web_page_preview=True)
        await state.clear()
        return

    reply = _format_response(text)

    urls = extract_urls(text)
    for u in urls[:3]:
        reply += "\n\n" + _format_url_result(u)

    await message.reply(reply, parse_mode="HTML", disable_web_page_preview=True)

    if current == ScanStates.waiting_for_message.state:
        await state.clear()
