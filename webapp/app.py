import os
import time
import threading
from pathlib import Path

from flask import Flask, jsonify, request

NAME = os.environ.get("SERVICE_NAME", "webapp")
DATA = Path("/data")
DATA.mkdir(exist_ok=True)

app = Flask(__name__)

@app.get("/")
def index():
    return jsonify(service=NAME, status="up")

@app.post("/upload")
def upload():
    saved = []
    for f in request.files.values():
        name = f"{int(time.time())}_{Path(f.filename).name}"
        f.save(DATA / name)
        saved.append(name)
    print(f"[{NAME}] upload from {request.remote_addr}: {saved}", flush=True)
    return jsonify(service=NAME, saved=saved), 201

@app.get("/files")
def files():
    return jsonify(service=NAME, files=sorted(p.name for p in DATA.iterdir()))

@app.post("/login")
def login():
    user = request.form.get("username") or (request.get_json(silent=True) or {}).get("username", "")
    return jsonify(service=NAME, logged_in=user)

def run_https(cert, key):
    app.run(host="0.0.0.0", port=443, ssl_context=(cert, key))


if __name__ == "__main__":
    cert = os.environ.get("TLS_CERT")
    key = os.environ.get("TLS_KEY")
    if cert and key:
        threading.Thread(target=run_https, args=(cert, key), daemon=True).start()
    app.run(host="0.0.0.0", port=80)