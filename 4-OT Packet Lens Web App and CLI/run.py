"""
Launcher Script for the ICS/OT PCAP Network Analyzer Web Application.
Starts the server and optionally opens the web browser.
"""

import argparse
import sys
import os
import webbrowser
import threading
import time

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import start_server

def open_browser_later(url: str, delay: float = 1.0):
    def _open():
        time.sleep(delay)
        print(f"[*] Opening browser at {url}...")
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()

def main():
    parser = argparse.ArgumentParser(description="Start ICS/OT PCAP Analyzer Web Application")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")
    parser.add_argument("--open-browser", action="store_true", default=False, help="Automatically open browser")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser")

    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print(r"""
  ___ ____ ____    _                _                     
 |_ _/ ___/ ___|  / \   _ __   __ _| |_   _ _______ _ __ 
  | | |   \___ \ / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
  | | |___ ___) / ___ \| | | | (_| | | |_| |/ /  __/ |   
 |___\____|____/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
                                      |___/               
    """)
    print(f"[*] Starting Web Dashboard on {url}")
    print("[*] Access the dashboard to upload PCAPs or analyze sample captures.")

    if args.open_browser and not args.no_browser:
        open_browser_later(url)

    start_server(args.host, args.port)

if __name__ == "__main__":
    main()
