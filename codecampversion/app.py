from flask import Flask, request, jsonify
from scanner import WebSecurityScanner
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target_url = data.get("url")

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    scanner = WebSecurityScanner(target_url)
    results = scanner.scan()

    return jsonify({
        "url": target_url,
        "vulnerabilities": results,
        "total": len(results)
    })

if __name__ == "__main__":
    app.run(debug=True)