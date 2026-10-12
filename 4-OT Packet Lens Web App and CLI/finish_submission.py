"""Generate verified local reports and package an evidence-complete ZIP.

From Windows / Antigravity PowerShell in this folder:
    python finish_submission.py

Uses the same private virtual environment as start.py; runs strict TShark
analysis on the user's machine. Does not fabricate results or disable security.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from start import ROOT, find_tshark, prepare_environment

STEPS = (
    ('Validate development captures', 'validate_development_captures.py'),
    ('Generate Mystery1/2/3 reports', 'regenerate_mystery_reports.py'),
    ('Create evidence-complete submission ZIP', 'prepare_submission.py'),
)


def main() -> int:
    try:
        python = prepare_environment()
        tshark = find_tshark()
        if not tshark:
            raise RuntimeError('TShark is not installed/found. Install Wireshark with TShark first.')
        env = os.environ.copy()
        env['OT_PACKET_LENS_TSHARK'] = tshark
        for label, file in STEPS:
            print(f'\n[Release] {label} ...', flush=True)
            subprocess.run([str(python), str(ROOT / file)], cwd=ROOT, env=env, check=True)
        print('\n[Release] Reports and submission archive generated successfully.', flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'\n[Release] Stopped: {exc}', file=sys.stderr)
        print('Fix the error above and rerun; previous results are not marked verified automatically.',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
