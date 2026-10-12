"""
Pure Python HTTP Server for Industrial PCAP Network Analyzer.
Built using standard library http.server (ThreadingHTTPServer) to ensure 100% compatibility
without external DLL dependencies or AppLocker/Application Control issues.
"""

import http.server
import json
import os
import sys
import uuid
import threading
import time
import mimetypes
import re
import urllib.parse
from email.parser import BytesParser
from email.policy import default
from typing import Dict, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# In a packaged Windows desktop build the UI is bundled read-only, but uploads
# and reports belong in a writable per-user directory. Source-mode behavior is
# unchanged when no override is set.
DATA_DIR = os.path.realpath(os.environ.get("OT_PACKET_LENS_DATA_DIR") or BASE_DIR)
SAMPLE_ROOT = os.path.realpath(os.environ.get("OT_PACKET_LENS_SAMPLE_ROOT") or BASE_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analyzer import PcapAnalyzer, ReportExporter

UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# In-memory job state store
jobs: Dict[str, Dict[str, Any]] = {}

# The dashboard is local-first. Loading a sample by path is limited to bundled
# PCAP directories; other files must be explicitly uploaded via the browser.
SAMPLE_DIRS = tuple(os.path.realpath(os.path.join(SAMPLE_ROOT, "pcaps", name))
                    for name in ("mystery", "samples"))
MAX_UPLOAD_BYTES = 512 * 1024 * 1024


def is_sample_capture_path(file_path):
    if not isinstance(file_path, str) or not file_path.lower().endswith((".pcap", ".pcapng", ".cap")):
        return False
    real = os.path.realpath(file_path)
    if not os.path.isfile(real):
        return False
    for root in SAMPLE_DIRS:
        try:
            if os.path.commonpath((real, root)) == root:
                return True
        except ValueError:
            # On Windows, unrelated drives do not have a common path.
            continue
    return False


def safe_capture_name(raw_name):
    # Safe for local storage and Content-Disposition; protects unusual names
    # from injecting HTTP response headers or creating invalid Windows paths.
    leaf = os.path.basename(str(raw_name).replace("\\", "/"))
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", leaf).strip("._")[:160]
    return cleaned or "capture.pcap"


def run_analysis_worker(job_id: str, file_path: str):
    """Worker thread that executes PCAP analysis."""
    jobs[job_id]["status"] = "processing"
    jobs[job_id]["start_time"] = time.time()

    def on_progress(packet_count: int, total_size: int, msg: str):
        jobs[job_id]["progress_packets"] = packet_count
        jobs[job_id]["message"] = msg

    try:
        analyzer = PcapAnalyzer(file_path, require_tshark=True)
        result = analyzer.analyze(progress_callback=on_progress)
        result["summary"]["filename"] = jobs[job_id]["filename"]
        jobs[job_id]["result"] = result
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["message"] = "Analysis finished successfully"
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["message"] = f"Analysis error: {str(e)}"

class ICSRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean logging
        if sys.stderr is not None:
            sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

    def send_json_response(self, data: Any, status_code: int = 200):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Desktop readiness probe: return 200 only when HTTP requests are served.
        if path == "/api/health":
            self.send_json_response({"status": "ok"})
            return

        # 1. Root SPA page
        if path in ["/", "/index.html"]:
            index_path = os.path.join(TEMPLATES_DIR, "index.html")
            with open(index_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. Static files
        if path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            static_file = os.path.abspath(os.path.join(STATIC_DIR, rel_path))
            if not static_file.startswith(os.path.abspath(STATIC_DIR) + os.sep):
                self.send_error(403, "Invalid static path")
                return
            if os.path.exists(static_file) and os.path.isfile(static_file):
                mime_type, _ = mimetypes.guess_type(static_file)
                if not mime_type:
                    if static_file.endswith(".css"): mime_type = "text/css"
                    elif static_file.endswith(".js"): mime_type = "application/javascript"
                    else: mime_type = "application/octet-stream"

                with open(static_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, "Static file not found")
                return

        # 3. API: List Samples
        if path == "/api/samples":
            samples = []
            mystery_dir = os.path.join(SAMPLE_ROOT, "pcaps", "mystery")
            if os.path.exists(mystery_dir):
                for fname in sorted(os.listdir(mystery_dir)):
                    if fname.lower().endswith((".pcap", ".pcapng", ".cap")):
                        fpath = os.path.join(mystery_dir, fname)
                        samples.append({
                            "name": fname,
                            "category": "Mystery Challenge PCAPs",
                            "path": fpath,
                            "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
                            "description": "Unknown capture content (verify after decoding)"
                        })

            samples_dir = os.path.join(SAMPLE_ROOT, "pcaps", "samples")
            if os.path.exists(samples_dir):
                for fname in sorted(os.listdir(samples_dir)):
                    if fname.lower().endswith((".pcap", ".pcapng", ".cap")):
                        fpath = os.path.join(samples_dir, fname)
                        category = "Development Sample"
                        if "modbus" in fname.lower(): category = "Modbus/TCP Sample"
                        elif "s7" in fname.lower(): category = "S7comm Sample"
                        elif "ethernet" in fname.lower() or "cip" in fname.lower(): category = "EtherNet/IP Sample"
                        elif "dnp3" in fname.lower(): category = "DNP3 Sample"
                        elif "bacnet" in fname.lower(): category = "BACnet/IP Sample"
                        elif "iec" in fname.lower(): category = "IEC 60870-5-104 Sample"

                        samples.append({
                            "name": fname,
                            "category": category,
                            "path": fpath,
                            "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
                            "description": f"Curated capture containing {category}"
                        })

            self.send_json_response({"samples": samples})
            return

        # 4. API: Job Status
        if path.startswith("/api/status/"):
            job_id = path[len("/api/status/"):]
            if job_id in jobs:
                j = jobs[job_id]
                self.send_json_response({
                    "job_id": job_id,
                    "filename": j.get("filename"),
                    "status": j.get("status"),
                    "progress_packets": j.get("progress_packets", 0),
                    "message": j.get("message"),
                    "error": j.get("error")
                })
            else:
                self.send_json_response({"error": "Job not found"}, 404)
            return

        # 5. API: Job Full Report
        if path.startswith("/api/report/"):
            job_id = path[len("/api/report/"):]
            if job_id in jobs:
                j = jobs[job_id]
                if j.get("status") == "completed":
                    self.send_json_response(j.get("result"))
                else:
                    self.send_json_response({"status": j.get("status"), "message": j.get("message")}, 202)
            else:
                self.send_json_response({"error": "Job not found"}, 404)
            return

        # 6. API: Report Exports
        if path.startswith("/api/export/"):
            parts = path[len("/api/export/"):].split("/")
            if len(parts) >= 2:
                job_id, fmt = parts[0], parts[1].lower()
                if job_id in jobs and jobs[job_id].get("status") == "completed":
                    res = jobs[job_id]["result"]
                    base_name = os.path.splitext(safe_capture_name(jobs[job_id]["filename"]))[0]

                    if fmt == "json":
                        content = ReportExporter.to_json(res).encode('utf-8')
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Disposition", f'attachment; filename="{base_name}_report.json"')
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        return
                    elif fmt == "csv-devices":
                        content = ReportExporter.to_csv_devices(res).encode('utf-8')
                        self.send_response(200)
                        self.send_header("Content-Type", "text/csv")
                        self.send_header("Content-Disposition", f'attachment; filename="{base_name}_devices.csv"')
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        return
                    elif fmt == "csv-flows":
                        content = ReportExporter.to_csv_conversations(res).encode('utf-8')
                        self.send_response(200)
                        self.send_header("Content-Type", "text/csv")
                        self.send_header("Content-Disposition", f'attachment; filename="{base_name}_flows.csv"')
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        return
                    elif fmt == "html":
                        content = ReportExporter.to_html(res).encode('utf-8')
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Disposition", f'attachment; filename="{base_name}_report.html"')
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        return
                    elif fmt in ["md", "markdown"]:
                        content = ReportExporter.to_markdown(res).encode('utf-8')
                        self.send_response(200)
                        self.send_header("Content-Type", "text/markdown; charset=utf-8")
                        self.send_header("Content-Disposition", f'attachment; filename="{base_name}_report.md"')
                        self.send_header("Content-Length", str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        return

            self.send_json_response({"error": "Export format or job invalid"}, 400)
            return

        self.send_error(404, "Endpoint not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. API: Analyze Local Path
        if path == "/api/analyze-path":
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > 16384:
                self.send_json_response({"error": "Invalid analysis request size"}, 413)
                return
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode('utf-8'))
                file_path = data.get("path")
                if not is_sample_capture_path(file_path):
                    self.send_json_response({"error": "Only bundled sample capture paths may be loaded here. Use Upload for other files."}, 403)
                    return

                file_path = os.path.realpath(file_path)
                job_id = str(uuid.uuid4())
                jobs[job_id] = {
                    "job_id": job_id,
                    "filename": safe_capture_name(file_path),
                    "file_path": file_path,
                    "status": "queued",
                    "progress_packets": 0,
                    "message": "Queued for analysis...",
                    "result": None,
                    "error": None
                }

                t = threading.Thread(target=run_analysis_worker, args=(job_id, file_path), daemon=True)
                t.start()

                self.send_json_response({"job_id": job_id, "status": "queued"})
            except Exception as e:
                self.send_json_response({"error": str(e)}, 500)
            return

        # 2. API: Upload File (Multipart parsing)
        if path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            if not content_type.startswith("multipart/form-data"):
                self.send_json_response({"error": "Content-Type must be multipart/form-data"}, 400)
                return

            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > MAX_UPLOAD_BYTES:
                self.send_json_response({"error": "Upload size exceeds the 512 MiB local-web limit; use CLI for larger captures."}, 413)
                return
            body = self.rfile.read(length)

            message = BytesParser(policy=default).parsebytes(
                ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode("utf-8") + body
            )
            if not message.is_multipart():
                self.send_json_response({"error": "Invalid multipart upload boundary"}, 400)
                return
            uploaded_filename = ""
            file_data = b""
            for part in message.iter_parts():
                if part.get_param("name", header="content-disposition") == "file" and part.get_filename():
                    uploaded_filename = safe_capture_name(part.get_filename())
                    file_data = part.get_payload(decode=True) or b""
                    break
            if not uploaded_filename.lower().endswith((".pcap", ".pcapng", ".cap")):
                self.send_json_response({"error": "Choose a .pcap, .pcapng or .cap file"}, 400)
                return

            if not file_data:
                self.send_json_response({"error": "No file content uploaded"}, 400)
                return

            job_id = str(uuid.uuid4())
            save_path = os.path.join(UPLOAD_DIR, f"{job_id}_{uploaded_filename}")
            with open(save_path, "wb") as f:
                f.write(file_data)

            jobs[job_id] = {
                "job_id": job_id,
                "filename": uploaded_filename,
                "file_path": save_path,
                "status": "queued",
                "progress_packets": 0,
                "message": "Upload complete. Enqueuing analysis...",
                "result": None,
                "error": None
            }

            t = threading.Thread(target=run_analysis_worker, args=(job_id, save_path), daemon=True)
            t.start()

            self.send_json_response({"job_id": job_id, "status": "queued", "filename": uploaded_filename})
            return

        self.send_error(404, "Endpoint not found")

def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Starts the ThreadingHTTPServer instance."""
    server = http.server.ThreadingHTTPServer((host, port), ICSRequestHandler)
    print(f"[*] Pure Python HTTP Server running at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.server_close()

if __name__ == "__main__":
    start_server()
