"""
Lightweight, zero-dependency HTTP server for the Sentinel Cybersecurity Dashboard.
Uses Python standard library only (http.server).
"""

import os
import sys
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
EVENTS_FILE = os.path.join(DASHBOARD_DIR, "events.json")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")


class SentinelDashboardHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving dashboard frontend and JSON endpoints.
    Binds strictly to localhost (127.0.0.1) for safety.
    """

    def log_message(self, format, *args):
        # Override to suppress noisy default request logs
        sys.stderr.write(f"[Sentinel Dashboard] {args[0]} {args[1]} -> {args[2]}\n")

    def _set_headers(self, status_code=200, content_type="application/json"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8080")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            index_path = os.path.join(DASHBOARD_DIR, "index.html")
            if os.path.exists(index_path):
                self._set_headers(200, "text/html; charset=utf-8")
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self._set_headers(404, "text/plain")
                self.wfile.write(b"Dashboard index.html not found.")
            return

        elif path == "/api/status":
            baseline_exists = os.path.isfile(BASELINE_FILE)
            baseline_count = 0
            baseline_time = None
            if baseline_exists:
                try:
                    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        baseline_count = len(data.get("items", {}))
                        baseline_time = data.get("created_at")
                except Exception:
                    pass

            events_count = 0
            if os.path.isfile(EVENTS_FILE):
                try:
                    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                        events_data = json.load(f)
                        events_count = len(events_data.get("events", []))
                except Exception:
                    pass

            payload = {
                "system": "Linux Persistence Change Sentinel",
                "version": "1.0.0",
                "mode": "DEMO / MOCK ENVIRONMENT",
                "is_demo": True,
                "mock_directory": os.path.join(BASE_DIR, "mock_linux"),
                "baseline_established": baseline_exists,
                "baseline_items_count": baseline_count,
                "baseline_created_at": baseline_time,
                "total_events_detected": events_count,
                "status": "CHANGES DETECTED" if events_count > 0 else "HEALTHY",
            }
            self._set_headers(200, "application/json")
            self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))
            return

        elif path == "/api/events":
            if os.path.isfile(EVENTS_FILE):
                try:
                    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                        content = f.read()
                    self._set_headers(200, "application/json")
                    self.wfile.write(content.encode("utf-8"))
                    return
                except Exception as e:
                    self._set_headers(500, "application/json")
                    self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                    return
            else:
                empty_response = {
                    "is_demo": True,
                    "last_scan": None,
                    "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                    "events": []
                }
                self._set_headers(200, "application/json")
                self.wfile.write(json.dumps(empty_response).encode("utf-8"))
                return

        elif path == "/api/baseline":
            if os.path.isfile(BASELINE_FILE):
                try:
                    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    # Strip huge content caches for API summary
                    summary_items = []
                    for p, item in data.get("items", {}).items():
                        summary_items.append({
                            "path": p,
                            "vector_name": item.get("vector_name"),
                            "mitre_id": item.get("mitre_id"),
                            "severity": item.get("severity"),
                            "exists": item.get("exists"),
                            "sha256": item.get("sha256"),
                        })
                    res = {
                        "version": data.get("version"),
                        "created_at": data.get("created_at"),
                        "total_items": data.get("total_items"),
                        "items": summary_items,
                    }
                    self._set_headers(200, "application/json")
                    self.wfile.write(json.dumps(res, indent=2).encode("utf-8"))
                    return
                except Exception as e:
                    self._set_headers(500, "application/json")
                    self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
                    return
            else:
                self._set_headers(404, "application/json")
                self.wfile.write(json.dumps({"error": "Baseline file not generated yet."}).encode("utf-8"))
                return

        self._set_headers(404, "text/plain")
        self.wfile.write(b"Not Found")


def run_dashboard_server(host: str = "127.0.0.1", port: int = 8080):
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    server = HTTPServer((host, port), SentinelDashboardHandler)
    print("=" * 65)
    print("  [SENTINEL] LINUX PERSISTENCE CHANGE DASHBOARD")
    print("=" * 65)
    print(f"  Status    : Running in SAFE DEMO MODE (Mock Environment)")
    print(f"  Access URL: http://{host}:{port}")
    print(f"  Security  : Bound to localhost only. No external access.")
    print("  Press Ctrl+C to stop the dashboard server.")
    print("=" * 65)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel dashboard server...")
        server.server_close()


if __name__ == "__main__":
    run_dashboard_server()
