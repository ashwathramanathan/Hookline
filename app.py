import os
from flask import Flask, jsonify, request, Response
from analyzer import analyze

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)


def load_page():
    # Works whether index.html is in templates/ or was uploaded next to app.py
    for path in (os.path.join(BASE, "templates", "index.html"), os.path.join(BASE, "index.html")):
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return f.read()
    return None


@app.get("/")
def index():
    page = load_page()
    if page is None:
        return "index.html was not found in the repository.", 500
    return Response(page, mimetype="text/html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))
    if not url.strip() or len(url) > 2048:
        return jsonify(error="Enter a URL under 2,048 characters."), 400
    try:
        return jsonify(analyze(url, live=bool(data.get("live", True))))
    except ValueError as e:
        return jsonify(error=str(e)), 400
