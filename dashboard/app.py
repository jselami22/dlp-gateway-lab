import json
import os
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template_string

LOG_FILE = Path(os.environ.get("DLP_LOG", "/logs/decisions.jsonl"))
EMPLOYEES = {
    "10.10.0.11": "alice",
    "10.10.0.12": "bob",
    "10.10.0.13": "carol",
}

app = Flask(__name__)

PAGE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <title>DLP Dashboard</title>
  <style>
    body   { font-family: system-ui, sans-serif; margin: 2rem; background: #f6f7f9; color: #222; }
    h1     { margin-bottom: 0.2rem; }
    .muted { color: #666; font-size: 0.9rem; }
    .cards { display: flex; gap: 1rem; margin: 1.5rem 0; }
    .card  { background: white; border-radius: 8px; padding: 1rem 1.5rem; box-shadow: 0 1px 3px #0002; }
    .card b { font-size: 2rem; display: block; }
    table  { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px #0002; }
    th, td { text-align: left; padding: 0.4rem 0.7rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
    th     { background: #fafafa; }
    .blocked { color: #b00020; font-weight: 600; }
    .allowed { color: #1b7a33; font-weight: 600; }
  </style>
</head>
<body>
  <h1>DLP Gateway</h1>
  <div class="muted">Last {{ recent|length }} decisions, refreshes every 5 seconds</div>

  <div class="cards">
    <div class="card"><b>{{ counts.get("blocked", 0) }}</b>blocked</div>
    <div class="card"><b>{{ counts.get("allowed", 0) }}</b>allowed</div>
    <div class="card">
      <span class="muted">Top block reasons</span>
      {% for reason, n in top_reasons %}<div>{{ n }} &times; {{ reason }}</div>{% endfor %}
    </div>
  </div>

  <table>
    <tr><th>Time (UTC)</th><th>Source</th><th>Who</th><th>Destination</th><th>Request</th><th>Verdict</th><th>Reason</th><th>Bytes</th></tr>
    {% for e in recent %}
    <tr>
      <td>{{ e.time[11:19] }}</td>
      <td>{{ e.source }}</td>
      <td>{{ e.who }}</td>
      <td>{{ e.host }}</td>
      <td>{{ e.what }}</td>
      <td class="{{ e.verdict }}">{{ e.verdict }}</td>
      <td>{{ e.reason }}</td>
      <td>{{ e.size }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


def load_decisions() -> list[dict]:
    """Read every decision from the log; skip lines that aren't valid JSON."""
    if not LOG_FILE.exists():
        return []
    decisions = []
    for line in LOG_FILE.read_text(errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entry["who"] = EMPLOYEES.get(entry.get("client", ""), entry.get("client", "?"))
        decisions.append(entry)
    return decisions


@app.get("/")
def index():
    decisions = load_decisions()
    counts = Counter(d.get("verdict") for d in decisions)
    reasons = Counter(d.get("reason", "").split(" in ")[0].split(" (")[0]
                      for d in decisions if d.get("verdict") == "blocked")
    return render_template_string(
        PAGE,
        recent=list(reversed(decisions[-100:])),
        counts=counts,
        top_reasons=reasons.most_common(5),
    )


@app.get("/api/decisions")
def api():
    return jsonify(load_decisions()[-100:])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)