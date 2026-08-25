#!/usr/bin/env python3
"""
Inspire - 1-Click Launcher Script
Starts the FastAPI web server and opens the Cyber Dashboard in your browser.
"""
import sys
import time
import webbrowser
import threading
import uvicorn

def open_browser(url: str, delay: float = 1.2):
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass

def main():
    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}"

    print("=" * 65)
    print(" 🛡️  INSPIRE — Web Vulnerability Scanner & Security Audit Suite")
    print("=" * 65)
    print(f" [*] Starting local web dashboard on: {url}")
    print(" [*] Opening your default browser automatically...")
    print(" [*] Press Ctrl+C in this terminal to stop the server.")
    print("=" * 65)

    # Launch browser in separate background thread
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    # Start FastAPI server
    uvicorn.run("app:app", host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
