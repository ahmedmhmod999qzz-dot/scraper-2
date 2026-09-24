"""web.py — خادم Flask بسيط"""
import os
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return {"status": "online", "service": "The Hunter v2"}


@app.route("/health")
def health():
    return {"ok": True}


def run_web():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
