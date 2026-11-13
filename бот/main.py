import asyncio
import logging
import os
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
load_dotenv(Path(__file__).resolve().parent / ".env")

from bot.handlers import text_handler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


async def main():
    token = os.getenv("BOT_TOKEN")
    if not token or token == "your_bot_token_here":
        raise RuntimeError("BOT_TOKEN не найден в .env")

    bot = Bot(token=token)
    dp = Dispatcher(storage=MemoryStorage())

    dp.include_router(text_handler.router)

    me = await bot.get_me()
    logging.info("Bot started: @%s", me.username)

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())