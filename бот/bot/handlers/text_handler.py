from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from bot.services.text_analyzer import analyze_text


router = Router(name="text_handler")

VERDICT_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}
VERDICT_LABEL = {"low": "Низкий риск", "medium": "Средний риск", "high": "Высокий риск"}


def _format_response(text: str) -> str:
    result = analyze_text(text)
    lines: list[str] = []
    lines.append(
        f"{VERDICT_EMOJI[result.verdict]} <b>{VERDICT_LABEL[result.verdict]}</b> — "
        f"{result.score}/100"
    )
    lines.append("━━━━━━━━━━━━")

    if not result.signals:
        lines.append("Признаков мошенничества не найдено.")
    else:
        lines.append("<b>Причины:</b>")
        for sig in result.signals[:3]:
            lines.append(f"• {sig.reason}")

    if result.is_suspicious:
        lines.append("")
        lines.append("⚠️ Не переходите по ссылкам и не сообщайте данные. Всегда уточняйте всю информацию у человека лично!")

    return "\n".join(lines)


@router.message(Command("start"))
async def cmd_start(message: Message):
    await message.answer(
        "Привет! Я бот, который помогает распознать мошенников.\n\n"
        "• Выбери нужную команду из списка и пришли мне <b>текст сообщения, файл или ссылку</b> — я проверю его на признаки скама\n"
        "/help — помощь",
        parse_mode="HTML",
    )


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "Список команд:\n"
        "•. /start - запустить бота.\n"
        "•. /scanmessage - проверить сообщение.\n"
        "•. /scanlink - проверить ссылку.\n"
        "•. /scanfile - проверить файл.\n\n"
        "Я не даю 100% гарантии — это помощник, а не приговор.",
    )


@router.message(Command("scanmessage"))
async def cmd_scan(message: Message):
    await message.answer("Пришлите ваше сообщение, пожалуйста.")

@router.message(lambda m: bool(m.text and m.text.startswith("/")))
async def unknown_command(message: Message):
    cmd = message.text.split()[0]

    await message.answer(
        f"❌ Некорректная команда: <code>{cmd}</code>\n\n",
        parse_mode="HTML",
    )

@router.message(Command("scanlink"))
async def cmd_scanlink(message: Message, state: FSMContext):
    await state.set_state(ScanStates.waiting_for_link)
    await message.answer("Пришлите ссылку, которую нужно проверить.\n(или /stop, чтобы отменить)")

@router.message()
async def handle_text(message: Message):
    text = (message.text or "").strip()
    if not text or text.startswith("/"):
        return

    if len(text) > 4000:
        await message.reply("Сообщение слишком длинное для анализа (макс. 4000 симв.).")
        return

    reply = _format_response(text)
    await message.reply(reply, parse_mode="HTML", disable_web_page_preview=True)
