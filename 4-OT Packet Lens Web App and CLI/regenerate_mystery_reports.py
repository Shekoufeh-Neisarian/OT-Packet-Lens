r"""Regenerate genuine TShark-based reports, never silently falling back to estimates.

Run from project root on the Windows machine with Wireshark/TShark installed:
    .\.venv\Scripts\python.exe regenerate_mystery_reports.py
To process development samples as well:
    python regenerate_mystery_reports.py --all
"""
from pathlib import Path
import argparse
from analyzer import PcapAnalyzer, ReportExporter

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description="Rebuild current (not historical) reports using TShark")
    parser.add_argument("--all", action="store_true", help="Include all development samples")
    args = parser.parse_args()
    capture_dirs = [ROOT / "pcaps" / "mystery"]
    if args.all:
        capture_dirs.append(ROOT / "pcaps" / "samples")
    captures = sorted(p for folder in capture_dirs for p in folder.iterdir()
                      if p.suffix.lower() in {".pcap", ".pcapng", ".cap"})
    if not captures:
        parser.error("No PCAPs found under pcaps/mystery")
    dest = ROOT / "reports"
    dest.mkdir(exist_ok=True)
    successes = 0
    for path in captures:
        print(f"\nAnalyzing {path.name} with Wireshark/TShark (this can take time)...", flush=True)
        try:
            report = PcapAnalyzer(str(path), require_tshark=True).analyze()
            if report["analysis_quality"]["mode"] != "wireshark_dissected":
                raise RuntimeError("Strict TShark required, but no dissector result")
        except Exception as exc:
            print(f"FAILED {path.name}: {exc}; no report written.", flush=True)
            continue
        target = dest / path.stem
        output = {".json": ReportExporter.to_json(report),
                  ".md": ReportExporter.to_markdown(report),
                  ".html": ReportExporter.to_html(report)}
        for extension, body in output.items():
            target.with_suffix(extension).write_text(body, encoding="utf-8")
        print(f"Saved JSON / Markdown / HTML for {path.name}: {report['summary']['packet_count']:,} frames.", flush=True)
        successes += 1
    if successes == len(captures) and all((dest / f"Mystery{n}.json").is_file() for n in (1, 2, 3)):
        from generate_investigation import generate
        generate()
    print(f"\nFinished {successes}/{len(captures)} capture reports successfully")
    return 0 if successes == len(captures) else 1


if __name__ == "__main__":
    raise SystemExit(main())
