"""Create a final ZIP from THIS local project, including genuinely generated reports.

Usage: python prepare_submission.py
Requires reports generated on the same Windows workspace for sign-off.
"""
from pathlib import Path
import sys, zipfile
ROOT = Path(__file__).resolve().parent
NAME = ROOT.name
OUT = ROOT.parent / (NAME + '_SUBMISSION_FROM_WINDOWS.zip')
REQUIRED_REPORTS = [ROOT / 'reports' / f'Mystery{i}.{ext}' for i in (1,2,3) for ext in ('json','md','html')]
REQUIRED_REPORTS += [ROOT/'reports'/'development_validation'/'DEVELOPMENT_CAPTURE_VALIDATION.md']
missing = [p for p in REQUIRED_REPORTS if not p.is_file()]
if missing:
    print('Cannot package an evidence-complete submission. Missing:', file=sys.stderr)
    for p in missing: print(' -', p.relative_to(ROOT), file=sys.stderr)
    print('First run regenerate_mystery_reports.py and validate_development_captures.py.', file=sys.stderr)
    raise SystemExit(2)
EXCLUDE_DIRS = {'.venv','venv','__pycache__','.git','node_modules','uploads','.pytest_cache'}
EXCLUDE_EXT = {'.pyc','.pyo','.tmp','.log'}
with zipfile.ZipFile(OUT, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
    for file in sorted(ROOT.rglob('*')):
        if not file.is_file(): continue
        relative = file.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS for part in relative.parts) or file.suffix in EXCLUDE_EXT: continue
        if file == OUT: continue
        z.write(file, str(Path(NAME) / relative))
print('Created:', OUT)
print('Contains real locally generated outputs. Provided GUI evidence is under docs/evidence; physical device identity and authorization remain inferred.')
