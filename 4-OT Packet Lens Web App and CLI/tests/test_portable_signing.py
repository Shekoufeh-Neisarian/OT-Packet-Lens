"""Qt onedir distribution and Windows signing tests (platform-independent)."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import build_desktop
import sign_release

class PortableTests(unittest.TestCase):
    def test_version_and_source(self):
        self.assertEqual(build_desktop.parse_tshark_version('TShark (Wireshark) 4.6.9 (Git)'), '4.6.9')
        self.assertEqual(build_desktop.source_filename('4.6.9'),'wireshark-4.6.9.tar.xz')
        with self.assertRaises(ValueError): build_desktop.source_filename('../oops')

    def test_qt_native_tree_included_in_zip(self):
        with tempfile.TemporaryDirectory() as folder:
            dist=Path(folder)/'dist'
            app=dist/'OT Packet Lens'
            (app/'Wireshark').mkdir(parents=True)
            (app/'sources').mkdir()
            (app/'_internal'/'PySide6').mkdir(parents=True)
            (app/'OT Packet Lens.exe').write_bytes(b'exe')
            (app/'_internal'/'PySide6'/'QtWebEngineProcess.exe').write_bytes(b'qt')
            (app/'Wireshark'/'tshark.exe').write_bytes(b'tshark')
            (app/'sources'/'wireshark-4.6.9.tar.xz').write_bytes(b'source')
            (app/'THIRD_PARTY_NOTICES.md').write_text('license')
            sign_release.verify_distribution_sources(app)
            sign_release.write_checksums(app)
            (app/'SIGNING_STATUS.txt').write_text('TEST SIGNATURE')
            archive=dist/'OT_Packet_Lens_Windows_Portable.zip'
            build_desktop.create_portable_zip(app,archive)
            with zipfile.ZipFile(archive) as z:
                self.assertIsNone(z.testzip())
                members=z.namelist()
                for rel in ('OT Packet Lens.exe','_internal/PySide6/QtWebEngineProcess.exe',
                            'Wireshark/tshark.exe','sources/wireshark-4.6.9.tar.xz',
                            'SHA256SUMS.txt','SIGNING_STATUS.txt'):
                    self.assertIn('OT Packet Lens/'+rel,members)

    def test_thumbprint_validation(self):
        thumb='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        self.assertEqual(sign_release.normalize_thumbprint(thumb),thumb)
        with self.assertRaises(ValueError):sign_release.normalize_thumbprint('bad')
        command=sign_release.sign_command(Path('signtool.exe'),Path('OT Packet Lens.exe'),thumbprint=thumb,timestamp='http://timestamp.test')
        self.assertIn('/fd',command)
        self.assertIn('SHA256',command)

    def test_safe_powershell_script(self):
        self.assertNotIn('Import-Module Microsoft.PowerShell.Security',sign_release.POWERSHELL_SIGNATURE_CHECK)
        self.assertNotIn('Get-ChildItem -CodeSigningCert',sign_release.POWERSHELL_SIGNATURE_CHECK)
        self.assertIn('HasPrivateKey',sign_release.POWERSHELL_SIGNATURE_CHECK)
        self.assertIn('1.3.6.1.5.5.7.3.3',sign_release.POWERSHELL_SIGNATURE_CHECK)
        with mock.patch.object(sign_release.subprocess,'run') as run:
            sign_release.powershell_sign_or_verify(Path('sample.exe'),
                thumbprint='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                action='sign',allow_self_signed=True)
            self.assertIn('OTPL_SIGN_THUMBPRINT',run.call_args.kwargs['env'])

    def test_non_windows_signing_guard(self):
        if os.name!='nt': self.assertEqual(sign_release.main(['--verify-only']),2)

if __name__=='__main__':unittest.main()
