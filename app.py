from flask import Flask, jsonify, render_template, request
from analyzer import analyze

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


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


if __name__ == "__main__":
    app.run(debug=False, port=5000)
