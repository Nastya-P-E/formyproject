import asyncio
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'бот'))
from bot.services import file_analyzer as files


class FileTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bot = Mock()
        self.bot.get_file = AsyncMock(return_value=SimpleNamespace(file_path='dummy'))
        async def download(path, destination, **kwargs):
            destination.write(b'harmless test')
        self.bot.download_file = AsyncMock(side_effect=download)
        self.env=patch.dict(os.environ, {'VIRUSTOTAL_ENABLED':'false','MALWAREBAZAAR_ENABLED':'false'})
        self.env.start()
        self.net=patch('requests.sessions.Session.request',side_effect=AssertionError('unexpected network'))
        self.net.start()

    async def asyncTearDown(self):
        self.net.stop();self.env.stop()

    async def test_no_keys_gives_unchecked_with_hash(self):
        r=await files.analyze_document(self.bot,'id','test.txt',13)
        self.assertIsNone(r.score)
        self.assertEqual(r.verdict,'unchecked')
        self.assertEqual(r.sha256,hashlib.sha256(b'harmless test').hexdigest())
        self.assertEqual((r.vt_status,r.mb_status),('disabled','disabled'))

    async def test_double_extension(self):
        r=await files.analyze_document(self.bot,'id','invoice.pdf.exe',13)
        self.assertEqual(r.verdict,'high')
        self.assertEqual(r.signals[0].id,'double_extension')

    async def test_too_large_does_not_download_or_claim_low(self):
        r=await files.analyze_document(self.bot,'id','file.exe',files.MAX_FILE_SIZE+1)
        self.bot.get_file.assert_not_called()
        self.assertIsNone(r.score)
        self.assertEqual(r.verdict,'unchecked')

    async def test_actual_download_limit_and_cleanup(self):
        original=tempfile.mkstemp
        paths=[]
        def create(*a,**k):
            fd,path=original(*a,**k);paths.append(path);return fd,path
        async def oversized(path,destination,**kwargs):destination.write(b'x'*9)
        self.bot.download_file.side_effect=oversized
        with patch.object(files.tempfile,'mkstemp',side_effect=create),patch.object(files,'MAX_FILE_SIZE',8):
            r=await files.analyze_document(self.bot,'id','test.txt',None)
        self.assertIsNone(r.score)
        self.assertIn('размер',r.note)
        self.assertTrue(paths)
        self.assertTrue(all(not Path(p).exists() for p in paths))

    async def test_download_failure_hides_exception_and_cleans_up(self):
        original=tempfile.mkstemp
        paths=[]
        def create(*a,**k):
            fd,path=original(*a,**k);paths.append(path);return fd,path
        self.bot.download_file.side_effect=RuntimeError('SECRET_DOWNLOAD_URL')
        with patch.object(files.tempfile,'mkstemp',side_effect=create):
            r=await files.analyze_document(self.bot,'id','test.txt',13)
        self.assertNotIn('SECRET',r.note)
        self.assertEqual(r.verdict,'unchecked')
        self.assertTrue(all(not Path(p).exists() for p in paths))

    async def test_vt_clean_error_missing_and_detection_are_distinct(self):
        for code,stats,status,verdict in (
            (200,{'malicious':0,'harmless':70},'completed','low'),
            (503,None,'error','unchecked'),
            (404,None,'not_found','unchecked'),
            (200,{},'pending','unchecked'),
            (200,{'malicious':1,'harmless':69},'completed','high'),
        ):
            response=Mock(status_code=code)
            response.json.return_value={'data':{'attributes':{'last_analysis_stats':stats}}}
            with self.subTest(status=status,verdict=verdict),patch.dict(os.environ,{'VIRUSTOTAL_ENABLED':'true','VIRUSTOTAL_API_KEY':'test-only'}),patch.object(files.requests,'get',return_value=response):
                r=await files.analyze_document(self.bot,'id','test.txt',13)
                self.assertEqual(r.vt_status,status)
                self.assertEqual(r.verdict,verdict)
                if status in ('error','not_found','pending'):self.assertIsNone(r.score)

    async def test_mb_auth_and_status(self):
        for data,expected in (({'query_status':'hash_not_found'},'not_found'),
                              ({'query_status':'ok','data':[{'sha256_hash':'dummy'}]},'completed'),
                              ({'query_status':'no_api_key'},'error')):
            response=Mock(status_code=200);response.json.return_value=data
            with patch.dict(os.environ,{'MALWAREBAZAAR_ENABLED':'true','MALWAREBAZAAR_API_KEY':'test-only'}),patch.object(files.requests,'post',return_value=response) as post:
                r=await files.analyze_document(self.bot,'id','test.txt',13)
                self.assertEqual(r.mb_status,expected)
                self.assertEqual(post.call_args.kwargs['headers'],{'Auth-Key':'test-only'})
                if expected=='completed':self.assertEqual(r.score,100)

    async def test_external_worker_keeps_loop_responsive(self):
        import threading
        started,release=threading.Event(),threading.Event()
        def slow(_):
            started.set();release.wait(2);return [],None,'disabled'
        with patch.object(files,'_check_virustotal_hash',slow):
            task=asyncio.create_task(files.analyze_document(self.bot,'id','test.txt',13))
            try:
                self.assertTrue(await asyncio.wait_for(asyncio.to_thread(started.wait,1),1.5))
                self.assertFalse(task.done())
            finally:release.set()
            await task


if __name__=='__main__':unittest.main()
