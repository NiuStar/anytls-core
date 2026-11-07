"""Offline regression contracts: download-only retry and pre-install diagnostics."""
import contextlib
import importlib.util
import io
import ssl
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location('download_binary_fixture', Path(__file__).with_name('install_binary_test.py'))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
b = f.b


class DownloadPhaseTests(unittest.TestCase):
    setUp = f.InstallerTests.setUp
    url = f.InstallerTests.url
    rebuild = f.InstallerTests.rebuild
    transport = f.InstallerTests.transport
    def test_transient_open_ssl_recovers_before_creating_target(self):
        target = self.root / 'download'
        attempts = []
        def transport(url, kind):
            attempts.append((url, kind))
            self.assertFalse(target.exists())
            if len(attempts) == 1:
                raise ssl.SSLEOFError(8, 'signed-url-secret')
            return io.BytesIO(b'payload')
        with mock.patch('time.sleep'):
            digest = b.i.download(self.url('SHA256SUMS'), target, transport=transport)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(target.read_bytes(), b'payload')
        self.assertEqual(digest, b.hashlib.sha256(b'payload').hexdigest())

    def test_download_failure_reports_no_dispatch_in_this_attempt(self):
        original_run = b.run
        def failed_transport(url, kind):
            raise ssl.SSLError(1, 'private-signed-url-secret')
        def isolated_run(args):
            return original_run(args, transport=failed_transport, system='Darwin', machine='arm64',
                                euid=501, home=self.home, runner=lambda *a, **k: self.fail('no process'))
        with mock.patch.object(b, 'run', side_effect=isolated_run), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(b.main([]), 1)
        text = err.getvalue()
        self.assertIn('download/verification failed', text)
        self.assertIn('no helper install, binary publish, WebUI signal or core reload dispatched in this attempt', text)
        self.assertIn('earlier UNKNOWN receipts retained', text)
        self.assertNotIn('may have been dispatched', text)
        self.assertNotIn('private-signed-url-secret', text)
        self.webui_factory.assert_not_called()


    def test_retry_classifier_narrow_and_bounded_for_all_get_consumers(self):
        eof = ssl.SSLError(ssl.SSL_ERROR_SSL, 'secret')
        eof.reason = 'UNEXPECTED_EOF_WHILE_READING'
        errors = (ssl.SSLEOFError(8, 'secret'), eof, ConnectionResetError(),
                  ConnectionAbortedError(), TimeoutError(),
                  b.i.urllib.error.URLError(ssl.SSLEOFError(8, 'secret')))
        for consumer in ('asset', 'json', 'update'):
            for error in errors:
                with self.subTest(consumer=consumer, error=type(error).__name__):
                    target = self.root / ('fresh-' + b.i.uuid.uuid4().hex)
                    opens = mock.Mock(side_effect=[error, io.BytesIO(b'{}')])
                    transport = b.update_transport(opens) if consumer == 'update' else opens
                    with mock.patch('time.sleep') as sleep, contextlib.redirect_stderr(io.StringIO()) as err:
                        if consumer == 'json':
                            self.assertEqual(b.i.read_json(b.i.API + '/releases/latest', transport=transport), {})
                        else:
                            b.i.download(self.url('SHA256SUMS'), target, transport=transport)
                            self.assertEqual(target.read_bytes(), b'{}')
                    self.assertEqual(opens.call_count, 2)
                    sleep.assert_called_once_with(0.5)
                    self.assertNotIn('secret', err.getvalue())
        for consumer, expected in (('normal', TimeoutError), ('update', b.DownloadFailed)):
            opens = mock.Mock(side_effect=TimeoutError())
            transport = b.update_transport(opens) if consumer == 'update' else opens
            with self.subTest(exhausted=consumer), mock.patch('time.sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(expected):
                b.i.read_json('fixture', transport=transport)
            self.assertEqual(opens.call_count, 2)
            sleep.assert_called_once()
        opens = mock.Mock(side_effect=TimeoutError())
        with mock.patch.object(b.i.time, 'monotonic', side_effect=[0, 30]), mock.patch('time.sleep') as sleep, self.assertRaises(TimeoutError):
            b.i.read_json('fixture', transport=opens)
        self.assertEqual(opens.call_count, 1)
        sleep.assert_not_called()

    def test_security_http_unknown_ssl_and_disk_errors_never_retry(self):
        cert = ssl.SSLCertVerificationError(1, 'secret')
        errors = [cert, b.i.urllib.error.URLError(cert), ssl.SSLError(1, 'secret'),
                  ValueError('untrusted redirect'), PermissionError('disk'), OSError(28, 'full')]
        # Real HTTP failures carry a response; None breaks Python 3.9 wrapper cleanup.
        errors += [b.i.urllib.error.HTTPError('https://secret', code, 'secret', {}, io.BytesIO(b'fixture'))
                   for code in (401, 403, 404, 429, 500)]
        for error in errors:
            if isinstance(error, b.i.urllib.error.HTTPError):
                def close_and_check(error=error):
                    error.close()
                    self.assertTrue(error.fp.closed)
                self.addCleanup(close_and_check)
            with self.subTest(error=type(error).__name__):
                target = self.root / 'absent'
                opens = mock.Mock(side_effect=error)
                with mock.patch('time.sleep') as sleep, self.assertRaises(type(error)) as caught:
                    b.i.download('fixture', target, transport=opens)
                self.assertIs(caught.exception, error)
                self.assertFalse(target.exists())
                self.assertEqual(opens.call_count, 1)
                sleep.assert_not_called()

    def test_body_read_disk_write_and_hash_parse_failures_never_replayed(self):
        class Partial(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise ssl.SSLEOFError(8, 'secret')
                return super().read(2)
        target = self.root / 'partial'
        opens = mock.Mock(return_value=Partial(b'payload'))
        with mock.patch('time.sleep') as sleep, self.assertRaises(ssl.SSLEOFError):
            b.i.download('fixture', target, transport=opens)
        self.assertEqual(opens.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual(target.read_bytes(), b'pa')
        # An existing exclusive target is never overwritten or removed.
        opens = mock.Mock(return_value=io.BytesIO(b'new'))
        with self.assertRaises(FileExistsError):
            b.i.download('fixture', target, transport=opens)
        self.assertEqual(target.read_bytes(), b'pa')
        self.assertEqual(opens.call_count, 1)
        for fault in ('write', 'flush', 'fsync'):
            opens = mock.Mock(return_value=io.BytesIO(b'payload'))
            failure = OSError(28, 'local-disk-secret')
            if fault == 'fsync':
                patcher = mock.patch.object(b.i.os, 'fsync', side_effect=failure)
            else:
                dst = mock.MagicMock()
                dst.__enter__.return_value = dst
                getattr(dst, fault).side_effect = failure
                patcher = mock.patch.object(Path, 'open', return_value=dst)
            with self.subTest(fault=fault), patcher, mock.patch('time.sleep') as sleep, self.assertRaises(OSError) as caught:
                b.i.download('fixture', self.root / fault, transport=b.update_transport(opens))
            self.assertIs(caught.exception, failure)
            self.assertNotIsInstance(caught.exception, b.DownloadFailed)
            self.assertEqual(opens.call_count, 1)
            sleep.assert_not_called()
        opens = mock.Mock(return_value=io.BytesIO(b'wrong'))
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            b.i.download('fixture', self.root / 'hash', expected='0'*64, transport=opens)
        self.assertEqual(opens.call_count, 1)
        opens = mock.Mock(return_value=io.BytesIO(b'{'))
        with self.assertRaises(ValueError):
            b.i.read_json('fixture', transport=opens)
        self.assertEqual(opens.call_count, 1)

    def test_transient_checksum_open_then_verified_check_is_process_free(self):
        calls = []
        def transport(url, kind):
            calls.append(url)
            if url.endswith('/SHA256SUMS') and calls.count(url) == 1:
                raise b.i.urllib.error.URLError(ssl.SSLEOFError(8, 'secret'))
            return self.transport(url, kind)
        args = b.argparse.Namespace(check_download=True, version=f.TAG, arch='arm64', reload_core=None)
        with mock.patch('time.sleep'), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            report = b.run(args, transport=transport, home=self.home,
                           runner=lambda *a, **k: self.fail('no execution'))
        self.assertTrue(report['download_verified'])
        self.assertFalse(report['executed'])
        self.assertEqual(calls.count(self.url('SHA256SUMS')), 2)
        self.assertEqual(len(calls), 5)
        self.assertFalse(self.app.exists())

    def test_native_open_keeps_strict_opener_fresh_request_and_short_timeout(self):
        opener = mock.Mock()
        opener.open.side_effect = [ssl.SSLEOFError(8, 'secret'), io.BytesIO(b'{}')]
        url = b.i.API + '/releases/latest'
        with mock.patch.object(b.i.urllib.request, 'build_opener', return_value=opener) as build, mock.patch('time.sleep'), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b.i.read_json(url), {})
        self.assertEqual(build.call_count, 2)
        first, second = [c.args[0] for c in opener.open.call_args_list]
        self.assertIsNot(first, second)
        self.assertEqual(first.full_url, url)
        self.assertEqual(first.get_method(), 'GET')
        self.assertEqual([c.kwargs for c in opener.open.call_args_list], [{'timeout': 15}, {'timeout': 15}])
        request = b.i.urllib.request.Request(self.url('SHA256SUMS'))
        for redirect in ('http://github.com/x', 'https://evil.example/x', 'https://user:secret@github.com/x'):
            with self.assertRaises(ValueError):
                b.i.Redirects('asset').redirect_request(request, None, 302, 'redirect', {}, redirect)
        with self.assertRaises(ValueError):
            b.i.Redirects('api').redirect_request(request, None, 302, 'redirect', {}, url)

    def test_preinstall_hash_and_archive_failures_keep_receipts_and_no_install(self):
        original_run = b.run
        self.app.mkdir()
        pending = self.app / 'core-reloads' / 'pending-sentinel'
        pending.parent.mkdir()
        pending.write_bytes(b'earlier-UNKNOWN')
        old = self.app / 'anytls-macos'
        old.write_bytes(b'old')
        for failure in (ValueError('SHA256 mismatch'), b.tarfile.ReadError('archive'), OSError(28, 'disk')):
            def isolated_run(args):
                return original_run(args, home=self.home, system='Darwin', machine='arm64', euid=501)
            with self.subTest(failure=type(failure).__name__), mock.patch.object(b, 'run', side_effect=isolated_run), mock.patch.object(b, 'verified_download', side_effect=failure), mock.patch.object(b, '_install_verified') as install, contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(b.main([]), 1)
            install.assert_not_called()
            self.assertIn('no helper install', err.getvalue())
            self.assertNotIn('may have been dispatched', err.getvalue())
            self.assertEqual(pending.read_bytes(), b'earlier-UNKNOWN')
            self.assertEqual(old.read_bytes(), b'old')

    def test_post_dispatch_unknown_warning_preserved_no_retry(self):
        with mock.patch.object(b, 'run', side_effect=ValueError('Core reload UNKNOWN; no retry')) as run, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(b.main([]), 1)
        run.assert_called_once()
        self.assertIn('may have been dispatched', err.getvalue())
        self.assertNotIn('no helper install', err.getvalue())


if __name__ == '__main__':
    unittest.main()
