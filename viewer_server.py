"""Serves heatmap_viewer.html and lets it start a scan.

Usage:
    python viewer_server.py            # http://localhost:7801/heatmap_viewer.html

POST /run {"repo": "repos/pygoat", "budget": 0.02}  -> starts attack_surface_scan.py
GET  /run-status                                    -> {"running", "progress", "result_file"}
GET  /results                                       -> {"repos": [...], "runs": {repo: [run files, newest first]}}
"""
import json
import subprocess
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7801
MAX_RUN_BUDGET_USD = json.loads((HERE / "classification_levels.json").read_text())["max_run_budget_usd"]
PYTHON = str(HERE / ".venv/bin/python") if (HERE / ".venv/bin/python").exists() else sys.executable
current_run = {"process": None, "result_file": None}


class ViewerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(HERE), **kwargs)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/results":
            repos = sorted(p.name for p in (HERE / "repos").iterdir() if p.is_dir())
            runs = {p.parent.parent.name: [] for p in HERE.glob("examples/*/runs/*.json")}
            for p in sorted(HERE.glob("examples/*/runs/*.json"), reverse=True):
                runs[p.parent.parent.name].append(str(p.relative_to(HERE)))
            return self.send_json({"repos": sorted(set(repos) | set(runs)), "runs": runs})
        if self.path != "/run-status":
            return super().do_GET()
        process = current_run["process"]
        progress_log = HERE / Path(current_run["result_file"] or "x").parent / "progress.log"
        last_line = progress_log.read_text().strip().splitlines()[-1:] if progress_log.exists() else []
        self.send_json({"running": bool(process and process.poll() is None),
                        "progress": last_line[0] if last_line else "",
                        "result_file": current_run["result_file"]})

    def do_POST(self):
        if self.path != "/run":
            return self.send_json({"error": "unknown path"}, 404)
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        repo, budget = request["repo"], float(request["budget"])
        if budget > MAX_RUN_BUDGET_USD:
            return self.send_json({"error": f"budget above max_run_budget_usd ({MAX_RUN_BUDGET_USD})"}, 400)
        if not (HERE / repo).is_dir():
            return self.send_json({"error": f"repo not found: {repo}"}, 400)
        if current_run["process"] and current_run["process"].poll() is None:
            return self.send_json({"error": "a scan is already running"}, 409)
        current_run["result_file"] = f"examples/{Path(repo).resolve().name}/scan_result.json"
        current_run["process"] = subprocess.Popen(
            [PYTHON, "attack_surface_scan.py", repo, "--budget", str(budget)], cwd=HERE)
        self.send_json({"started": True, "result_file": current_run["result_file"]})


if __name__ == "__main__":
    print(f"http://localhost:{PORT}/heatmap_viewer.html")
    ThreadingHTTPServer(("", PORT), ViewerHandler).serve_forever()
