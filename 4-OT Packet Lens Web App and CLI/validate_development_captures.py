"""Validate bundled DEVELOPMENT captures against independent TShark dissections.

Run on a computer with dpkt and Wireshark/TShark installed:
    python validate_development_captures.py

This does not establish physical device identity or whether a command was
executed on a PLC. GUI reviewer sign-off is deliberately separate.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
DEFAULT_CAPTURES = (
    ROOT / 'pcaps' / 'samples' / 'ModbusTCP_ModbusTCP.pcap',
    ROOT / 'pcaps' / 'samples' / 's7_S7-1200-Uploading-OB1-TIAV12.pcap',
    # Supplementary POSITIVE S7comm control, separate from the two dev captures.
    ROOT / 'pcaps' / 'mystery' / 'Mystery3.pcap',
)
# Coverage expectations are sample-specific; filenames guide test expectations,
# but are not themselves protocol evidence. Any ambiguity remains documented.
COVERAGE = {
    'ModbusTCP_ModbusTCP.pcap': ('modbus',),
    's7_S7-1200-Uploading-OB1-TIAV12.pcap': ('tpkt', 'cotp'),
    'Mystery3.pcap': ('s7comm',),
}

FILTERS = ('tcp', 'udp', 'arp', 'icmp', 'modbus', 'mbtcp', 's7comm', 'tpkt', 'cotp', 'dns', 'enip', 'dnp3')
FIELDS = {'Modbus/TCP': 'modbus.func_code', 'S7comm': 's7comm.param.func'}


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def compare_counts(stored, independent, fields=FILTERS):
    """Keep zeroes and mismatches visible. No silent omissions."""
    return [dict(filter=name, app_frames=int(stored.get(name, 0)),
                 independent_frames=int(independent.get(name, 0)),
                 difference=int(stored.get(name, 0)) - int(independent.get(name, 0)),
                 status='MATCH' if int(stored.get(name, 0)) == int(independent.get(name, 0)) else 'DIFFERENCE')
            for name in fields]


def tshark_field_occurrences(exe, capture, field):
    """Independently count numeric decoded field occurrences, not just frames."""
    command = [exe, '-n', '-r', str(capture), '-T', 'fields', '-e', field,
               '-E', 'occurrence=a', '-E', 'aggregator=,']
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding='utf-8', errors='replace') as proc:
        count = 0
        for line in proc.stdout:
            for token in line.strip().split(','):
                token = token.strip()
                if token:
                    # Numeric codes use decimal or explicit 0x.. notation.
                    try:
                        int(token, 16 if token.lower().startswith('0x') else 10)
                    except ValueError:
                        continue
                    count += 1
        stderr = proc.stderr.read()
        code = proc.wait()
        if code:
            raise RuntimeError(f'TShark field {field} failed: {stderr[:600]}')
        return count


def coverage_status(filename, independently_decoded):
    """Return positive evidence, not merely equality of two zero counts."""
    expected = COVERAGE.get(filename, ())
    missing = [key for key in expected if int(independently_decoded.get(key, 0)) <= 0]
    if missing:
        return {'status': 'MISSING_EXPECTED_PROTOCOL', 'positive_layers': list(expected),
                'notes': 'No independently decoded frames for expected protocols: ' + ', '.join(missing)}
    if filename == 's7_S7-1200-Uploading-OB1-TIAV12.pcap':
        if independently_decoded.get('s7comm', 0) == 0:
            return {'status': 'LIMITED_TO_ISO_ON_TCP', 'positive_layers': list(expected),
                    'notes': 'TPKT/COTP are decoded; S7comm is NOT decoded. This sample cannot validate S7 function parsing.'}
    if expected:
        return {'status': 'POSITIVE_PROTOCOL_DETECTED', 'positive_layers': list(expected),
                'notes': 'Expected decoded protocol(s) present; GUI and content review remain pending.'}
    return {'status': 'NO_PREDEFINED_PROTOCOL_EXPECTATION', 'positive_layers': [],
            'notes': 'Protocol-count comparison only; no positive protocol detection target selected.'}


def as_markdown(results, timestamp, tshark_version):
    lines = [
        '# Development-capture accuracy validation + optional positive controls', '',
        f'Generated (UTC): {timestamp}',
        f'Wireshark engine: `{tshark_version}`', '',
        '## Evidence levels', '',
        '- **Observed facts:** captured frame records, IP addresses, ports, timestamps, and packet bytes. These are observations *in the capture*, not independently verified physical truth.',
        '- **Derived information:** TShark-dissected protocol labels, decoded function fields, statistics, MAC/OUI vendor lookups and correlations. These require matching decoding configuration and may not be unique transactions.',
        '- **Inferences:** PLC/HMI/Engineering Workstation roles, malicious intent, scan hypotheses and alert severity. They require human confirmation and operational context.', '',
        'TShark validation below runs independent `-Y` display filters on the **same capture bytes**. It does not by itself prove the Wireshark GUI used identical decoding preferences.', '',
    ]
    for r in results:
        lines += [f'## {r["filename"]}', '',
                  f'- Capture SHA-256: `{r["sha256"]}`',
                  f'- Application frames: **{r.get("app_frames", "not available")}**',
                  f'- Independent TShark frames: **{r.get("independent_frames", "not available")}**',
                  f'- Frame count result: **{r.get("frame_status", "NOT RUN")}**',
                  f'- Strict analyzer: `{r.get("analysis_mode", "not available")}`',
                  '', '| Filter | Application protocol-presence frames | Independent `-Y` frames | Difference | Result |',
                  '|---|---:|---:|---:|---|']
        for row in r.get('filters', []):
            lines.append(f'| `{row["filter"]}` | {row["app_frames"]:,} | {row["independent_frames"]:,} | {row["difference"]:+,} | {row["status"]} |')
        coverage = r.get('coverage', {})
        lines += ['', f'**Positive protocol coverage:** {coverage.get("status", "NOT EVALUATED")} — {coverage.get("notes", "")}', '', '| Decoded field | Application occurrences | Independent TShark occurrences | Result |',
                  '|---|---:|---:|---|']
        for row in r.get('fields', []):
            lines.append(f'| `{row["field"]}` | {row["app_occurrences"]:,} | {row["independent_occurrences"]:,} | {row["status"]} |')
        if r.get('differences'):
            lines += ['', '**Differences requiring investigation:**', '']
            lines += [f'- {s}' for s in r['differences']]
        else:
            lines += ['', '**Automated comparisons:** no differences in the selected metrics (not proof that every protocol or device role is correct).']
        lines += ['', '### Manual Wireshark GUI / asset review — pending', '',
                  '- [ ] Open this exact PCAP in Wireshark and confirm Capture File Properties frame count.',
                  '- [ ] Apply `modbus`, `mbtcp`, `s7comm`, `tpkt`, `cotp`, `tcp`, `udp`, `arp` as applicable and compare **Displayed** frames with the table.',
                  '- [ ] Inspect several decoded function fields in Packet Details; look for reassembly warnings or malformed frames.',
                  '- [ ] Review endpoint/port findings with Statistics → Endpoints and Conversations.',
                  '- [ ] Verify vendor identities and suspected PLC/HMI/EWS roles with known network documentation; write down disagreements.',
                  '- [ ] Record Wireshark version, decoding preferences, reviewer/date and corrective actions.', '',
                  '**Role inferences: NOT independently confirmed.**', '']
    lines += ['## Reference scope', '', 'The two development captures are ModbusTCP_ModbusTCP.pcap and s7_S7-1200-Uploading-OB1-TIAV12.pcap. Mystery3.pcap is included as an additional positive S7comm control. Zero-vs-zero S7comm on the ISO-on-TCP-only sample is reported as LIMITED, not validation of S7 functions.', '', '## Review log / corrective actions', '',
              '| Capture | GUI reviewer/date | Difference or limitation | Correction implemented | Re-test status |',
              '|---|---|---|---|---|']
    for r in results:
        title = str(r.get('filename', 'Unknown')).replace('|', '/')
        explanation = str(r.get('coverage', {}).get('notes', 'Inspect decoded payloads and role evidence')).replace('|', '/')
        lines.append(f'| {title} | Pending | {explanation} | Pending GUI review | Not signed off |')
    lines += ['', 'Do not mark this review complete until the human inspection is performed. Any machine-generated MATCH only validates that particular filter or field count.']
    return '\n'.join(lines) + '\n'


def validate_one(path, tshark, count_frames, analyzer_class):
    print(f'Analyzing development capture: {path.name}', flush=True)
    app = analyzer_class(str(path), require_tshark=True).analyze()
    quality = app.get('analysis_quality', {})
    if quality.get('mode') != 'wireshark_dissected':
        raise RuntimeError('The analyzer did not complete strict TShark mode')
    ref = app.get('wireshark_reference') or {}
    app_total = int(app['summary']['packet_count'])
    independent_total = count_frames(tshark, path, 'frame')
    direct = {}
    for name in FILTERS:
        direct[name] = count_frames(tshark, path, name)
    comparisons = compare_counts(ref.get('display_filter_packet_counts') or {}, direct)
    functions = []
    for group, field in FIELDS.items():
        app_fields = ref.get('function_code_occurrences', {}).get(group, {})
        app_n = sum(int(v) for v in app_fields.values())
        direct_n = tshark_field_occurrences(tshark, path, field)
        functions.append({'field': field, 'app_occurrences': app_n, 'independent_occurrences': direct_n,
                          'status': 'MATCH' if app_n == direct_n else 'DIFFERENCE'})
    diffs = []
    if app_total != independent_total:
        diffs.append(f'Frame mismatch: application {app_total:,}, independent TShark {independent_total:,}.')
    diffs += [f'{d["filter"]}: app {d["app_frames"]:,} vs independent {d["independent_frames"]:,} (difference {d["difference"]:+,}). Frame.protocols presence can differ from -Y filter matching; investigate decoder preferences, encapsulation, or parser logic.'
              for d in comparisons if d['status'] != 'MATCH']
    diffs += [f'{d["field"]}: app {d["app_occurrences"]:,} decoded fields versus {d["independent_occurrences"]:,} independent occurrences.'
              for d in functions if d['status'] != 'MATCH']
    return {
        'filename': path.name, 'path': str(path), 'sha256': digest_file(path),
        'app_frames': app_total, 'independent_frames': independent_total,
        'frame_status': 'MATCH' if app_total == independent_total else 'DIFFERENCE',
        'analysis_mode': quality.get('mode'), 'filters': comparisons,
        'coverage': coverage_status(path.name, direct),
        'fields': functions, 'differences': diffs,
        'suspected_roles_unverified': [
            {'ip': ip, 'role': d.get('suspected_role'), 'confidence': d.get('confidence'),
             'evidence': d.get('evidence', [])[:5]}
            for ip,d in app.get('devices', {}).items() if d.get('is_ot_asset')
        ][:10],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Review 2+ development captures with strict Python + independent TShark validation')
    parser.add_argument('captures', nargs='*', type=Path, help='Override default Modbus, S7-COTP, and Mystery3 positive-control captures')
    parser.add_argument('--output-dir', default='reports/development_validation', type=Path)
    args = parser.parse_args(argv)
    captures = [p.resolve() for p in (args.captures or DEFAULT_CAPTURES)]
    if len(captures) < 2:
        parser.error('Supply at least two development captures')
    for capture in captures:
        if not capture.is_file():
            parser.error(f'Missing development PCAP: {capture}')
    # Import runtime dependencies only when real validation is requested;
    # pure report/difference helper functions are testable separately.
    from analyzer import PcapAnalyzer
    from analyzer.wireshark_reference import find_tshark
    from verify_parity import count_frames
    tshark = find_tshark()
    if not tshark:
        parser.error('Wireshark/TShark is required (install Wireshark with TShark)')
    ver = subprocess.run([tshark, '--version'], capture_output=True, text=True, timeout=20, check=True).stdout.splitlines()[0]
    results = []
    failed = 0
    for capture in captures:
        try:
            result = validate_one(capture, tshark, count_frames, PcapAnalyzer)
            failed += bool(result['differences']) or result.get('coverage', {}).get('status') == 'MISSING_EXPECTED_PROTOCOL'
            results.append(result)
            print(f'{capture.name}: {result["frame_status"]}; {len(result["differences"])} count differences; coverage={result["coverage"]["status"]}', flush=True)
        except Exception as exc:
            failed += 1
            print(f'{capture.name}: ERROR: {exc}', file=sys.stderr, flush=True)
            results.append({'filename': capture.name, 'sha256': digest_file(capture),
                            'frame_status': 'ERROR', 'differences': [f'Analysis failed: {exc}']})
    args.output_dir.mkdir(parents=True, exist_ok=True)
    created = datetime.now(timezone.utc).isoformat()
    evidence = {'generated_utc': created, 'tshark_version': ver, 'captures': results,
                'automatic_checks_passed': failed == 0,
                'manual_gui_review': 'PENDING — no manual Wireshark GUI or ground-truth asset identification is implied'}
    (args.output_dir / 'development_validation.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    (args.output_dir / 'DEVELOPMENT_CAPTURE_VALIDATION.md').write_text(as_markdown(results, created, ver), encoding='utf-8')
    print('Wrote:', args.output_dir.resolve())
    print('Automated count parity:', 'PASS' if failed == 0 else 'DIFFERENCES — review generated report')
    print('Manual Wireshark GUI review: PENDING (see markdown checklist)')
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
