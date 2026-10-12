"""Launcher tests: no Wireshark installation, network or pip downloads needed."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

MAIN = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ot_project_start', MAIN / 'start.py')
start = importlib.util.module_from_spec(spec)
spec.loader.exec_module(start)


class AutoStartTests(unittest.TestCase):
    def test_digest_changes_with_requirements(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / 'requirements.txt').write_text('dpkt>=1.9.8\n')
            with mock.patch.object(start, 'ROOT', p):
                first = start.requirements_fingerprint()
                (p / 'requirements.txt').write_text('dpkt==1.9.8\n')
                self.assertNotEqual(first, start.requirements_fingerprint())

    def test_existing_valid_environment_skips_install(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); venv = root / '.venv'; venv.mkdir()
            python = venv / ('Scripts/python.exe' if start.os.name == 'nt' else 'bin/python')
            python.parent.mkdir(parents=True); python.touch()
            (root / 'requirements.txt').write_text('dpkt>=1.9.8')
            with mock.patch.multiple(start, ROOT=root, VENV=venv, STAMP=venv / '.stamp'), \
                mock.patch.object(start, 'interpreter_healthy', return_value=True), \
                mock.patch.object(start, 'dependencies_healthy', return_value=True), \
                mock.patch.object(start.subprocess, 'run') as runner:
                start.STAMP.write_text(start.requirements_fingerprint())
                self.assertEqual(start.prepare_environment(), python)
                runner.assert_not_called()

    def test_first_run_creates_env_and_installs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); venv = root / '.venv'; python = venv / ('Scripts/python.exe' if start.os.name == 'nt' else 'bin/python')
            (root / 'requirements.txt').write_text('dpkt>=1.9.8')
            def fake_run(cmd, **kw):
                if cmd[1:3] == ['-m', 'venv']:
                    python.parent.mkdir(parents=True, exist_ok=True); python.touch()
                return mock.Mock(returncode=0)
            with mock.patch.multiple(start, ROOT=root, VENV=venv, STAMP=venv / '.stamp'), \
                 mock.patch.object(start, 'interpreter_healthy', return_value=True), \
                 mock.patch.object(start, 'dependencies_healthy', return_value=True), \
                 mock.patch.object(start.subprocess, 'run', side_effect=fake_run) as runner:
                self.assertEqual(start.prepare_environment(), python)
                self.assertEqual(runner.call_count, 2)
                self.assertTrue(start.STAMP.exists())

    def test_broken_environment_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); venv = root / '.venv'; venv.mkdir()
            (venv / 'sentinel.txt').write_text('keep this')
            with mock.patch.multiple(start, ROOT=root, VENV=venv, STAMP=venv / '.stamp'), \
                 mock.patch.object(start, 'interpreter_healthy', return_value=False):
                with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                    start.prepare_environment()
                self.assertTrue((venv / 'sentinel.txt').exists())

    def test_tshark_override(self):
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / 'tshark.exe'; executable.touch()
            with mock.patch.dict(start.os.environ, {'OT_PACKET_LENS_TSHARK': str(executable)}):
                self.assertEqual(start.find_tshark(), str(executable))

    def test_doctor_does_not_install_or_launch(self):
        with mock.patch.object(start, 'prepare_environment') as install, \
             mock.patch.object(start, 'find_tshark', return_value=None), \
             mock.patch.object(start, 'interpreter_healthy', return_value=False), \
             mock.patch.object(start, 'dependencies_healthy', return_value=False), \
             mock.patch.object(start, 'port_available', return_value=True), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(start.main(['--doctor']), 0)
            install.assert_not_called()
            self.assertIn('NOT FOUND', output.getvalue())

    def test_setup_only_does_not_start(self):
        with mock.patch.object(start, 'prepare_environment', return_value=Path('python')), \
             mock.patch.object(start, 'launch_server') as server, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(start.main(['--setup-only']), 0)
            server.assert_not_called()

    def test_busy_port_prevents_second_server(self):
        with mock.patch.object(start, 'port_available', return_value=False), \
             mock.patch.object(start.subprocess, 'Popen') as child, \
             contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(start.launch_server(Path('python'), 'tshark', 8000, False), 3)
            child.assert_not_called()
            self.assertIn('already in use', output.getvalue())

    def test_delayed_ready_server_opens_browser(self):
        child = mock.Mock()
        child.poll.return_value = None
        child.wait.return_value = 0
        with mock.patch.object(start, 'port_available', return_value=True), \
             mock.patch.object(start, 'server_ready', side_effect=[False, True]), \
             mock.patch.object(start.subprocess, 'Popen', return_value=child) as popen, \
             mock.patch.object(start.time, 'sleep'), \
             mock.patch.object(start.webbrowser, 'open', return_value=True) as browser, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(start.launch_server(Path('python'), 'tshark', 8000, False), 0)
            self.assertIn('--no-browser', popen.call_args.args[0])
            self.assertEqual(popen.call_args.kwargs['env']['OT_PACKET_LENS_TSHARK'], 'tshark')
            browser.assert_called_once_with('http://127.0.0.1:8000/')

    def test_server_exits_before_ready_no_browser(self):
        child = mock.Mock()
        child.poll.return_value = 1
        with mock.patch.object(start, 'port_available', return_value=True), \
             mock.patch.object(start.subprocess, 'Popen', return_value=child), \
             mock.patch.object(start, 'server_ready') as ready, \
             mock.patch.object(start.webbrowser, 'open') as browser, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(start.launch_server(Path('python'), 'tshark', 8000, False), 1)
            ready.assert_not_called()
            browser.assert_not_called()


if __name__ == '__main__':
    unittest.main()
