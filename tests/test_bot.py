import asyncio
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'бот'))
from aiogram import Bot, Dispatcher
from aiogram.types import Chat, Message, MessageEntity, Update, User, Document, PhotoSize
from bot.services import url_analyzer as urls
from bot.handlers import text_handler as handlers


class UrlTests(unittest.TestCase):
    def test_rejects_invalid_input(self):
        for value in ('это не ссылка', 'https://[broken', 'file://example.com',
                      'https://user:password@example.com', 'https://example.com/<b>'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                urls.analyze_url(value, use_virustotal=False)

    def test_local_analysis_never_makes_requests(self):
        with patch('requests.sessions.Session.request', side_effect=AssertionError('network')):
            self.assertEqual(urls.analyze_url('https://docs.python.org/3/', False).score, 0)
            result = urls.analyze_url('https://192.0.2.1/login', False)
            self.assertTrue(result.is_suspicious)
            self.assertIn('ip_host', [s.id for s in result.signals])

    def test_vt_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(urls.requests, 'get') as get:
            result = urls.analyze_url('https://example.com')
            self.assertEqual(result.vt_status, 'disabled')
            get.assert_not_called()

    def test_vt_reads_environment_at_call_and_distinguishes_statuses(self):
        with patch.dict(os.environ, {'VIRUSTOTAL_ENABLED':'true', 'VIRUSTOTAL_API_KEY':'test-only'}):
            for code, payload, expected in (
                (404, {}, 'not_found'), (429, {}, 'error'),
                (200, {'data':{'attributes':{}}}, 'pending'),
                (200, {'data':{'attributes':{'last_analysis_stats':{'malicious':1,'harmless':70}}}}, 'completed'),
            ):
                response = Mock(status_code=code)
                response.json.return_value = payload
                with self.subTest(code=code, expected=expected), patch.object(urls.requests, 'get', return_value=response), patch.object(urls.requests, 'post') as post:
                    result = urls.analyze_url('https://example.com')
                    self.assertEqual(result.vt_status, expected)
                    if expected == 'completed': self.assertTrue(result.is_suspicious)
                    post.assert_not_called()

    def test_vt_skips_private_addresses(self):
        with patch.dict(os.environ, {'VIRUSTOTAL_ENABLED':'true', 'VIRUSTOTAL_API_KEY':'test-only'}), patch.object(urls.requests, 'get') as get:
            self.assertEqual(urls.analyze_url('http://127.0.0.1').vt_status,'private_url')
            get.assert_not_called()


class RoutingTests(unittest.IsolatedAsyncioTestCase):
    async def test_commands_states_invalid_url_and_attachment(self):
        bot = Bot('123456789:' + 'A' * 35)
        dp = Dispatcher()
        dp.include_router(handlers.router)
        replies = []
        async def capture(message, text, **kwargs): replies.append(text)
        async def send(text=None, document=None, photo=None):
            replies.clear()
            entities = [MessageEntity(type='bot_command', offset=0, length=len(text.split()[0]))] if text and text.startswith('/') else []
            message = Message(message_id=1, date=datetime.now(timezone.utc),
                              chat=Chat(id=42,type='private'),from_user=User(id=42,is_bot=False,first_name='Test'),
                              text=text,entities=entities,document=document,photo=photo)
            await dp.feed_update(bot, Update(update_id=1,message=message))
            self.assertTrue(replies)
            return replies[0]
        try:
            with patch.object(Message, 'answer', capture), patch.object(Message, 'reply', capture), patch('requests.sessions.Session.request', side_effect=AssertionError('network')), patch.dict(os.environ, {'VIRUSTOTAL_ENABLED':'false'}):
                self.assertIn('/scanlink', await send('/start'))
                await send('/scanlink')
                self.assertIn('Некорректная ссылка', await send('https://[broken'))
                await send('/scanlink')
                self.assertIn('одну ссылку', await send('это не ссылка'))
                await send('/scanlink')
                self.assertIn('66.0', await send('https://192.0.2.1/login'))
                await send('/scanmessage')
                self.assertIn('23.8', await send('Привет! Как дела?'))
                await send('/scanlink')
                self.assertIn('остановлена', await send('/stop'))
                self.assertIn('&lt;b&gt;', await send('/<b>'))
                self.assertIn('Фото', await send(photo=[PhotoSize(file_id='test',file_unique_id='test',width=10,height=10)]))
                await send('/scanfile')
                self.assertIn('Ожидаю документ', await send('текст вместо файла'))
                self.assertIn('остановлена', await send('/stop'))
                from types import SimpleNamespace
                async def download(self, file_path, destination, **kwargs):
                    destination.write(b'harmless test')
                async def get_file(self, file_id):
                    return SimpleNamespace(file_path='dummy')
                with patch.object(Bot,'get_file',get_file), patch.object(Bot,'download_file',download), patch.dict(os.environ, {'MALWAREBAZAAR_ENABLED':'false'}):
                    await send('/scanfile')
                    await send(document=Document(file_id='test',file_unique_id='test',file_name='<b>report.txt',file_size=13))
                    self.assertIn('SHA-256', replies[-1])
                    self.assertIn('&lt;b&gt;report.txt', replies[-1])
                    self.assertIn('Безопасность не определена', replies[-1])
                    self.assertIn('отключён', replies[-1])
        finally:
            await dp.storage.close()
            await bot.session.close()

    async def test_url_work_does_not_block_event_loop(self):
        import threading
        started, release = threading.Event(), threading.Event()
        def slow(_):
            started.set()
            release.wait(2)
            return 'done'
        with patch.object(handlers, '_format_url_result', slow):
            task = asyncio.create_task(handlers._url_response('https://example.com'))
            try:
                await asyncio.wait_for(asyncio.to_thread(started.wait, 1), timeout=1.5)
                self.assertFalse(task.done())
                # Reaching this line while the worker is waiting proves the loop is free.
                release.set()
                self.assertEqual(await task, 'done')
            finally:
                release.set()


if __name__ == '__main__':
    unittest.main()
