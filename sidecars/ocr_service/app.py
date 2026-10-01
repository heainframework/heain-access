"""OCR sidecar for heain-access's id_card Stage A verifier.

Wraps EasyOCR (a real trained text-detection + recognition model, not a
placeholder) behind a tiny Flask HTTP API -- mirroring the Python-sidecar
pattern already used by heain-image (rembg/upscale) and heain-videos
(restoration): the ML model lives in Python, the deterministic business
logic (comparing the extracted ID number against the expected one) stays
in heain-access's own Go code (internal/verifier/idcard.go).
"""
import base64
import io

from flask import Flask, request, jsonify
import easyocr
from PIL import Image
import numpy as np

app = Flask(__name__)

# Thai + English: a real Thai national ID card carries both scripts.
reader = easyocr.Reader(["th", "en"], gpu=False)


@app.route("/extract", methods=["POST"])
def extract():
    data = request.get_json(force=True)
    image_b64 = data.get("image_b64", "")
    if not image_b64:
        return jsonify({"error": "image_b64 is required"}), 400

    try:
        image_bytes = base64.b64decode(image_b64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as exc:
        return jsonify({"error": f"could not decode image: {exc}"}), 400

    results = reader.readtext(np.array(image))
    if not results:
        return jsonify({"text": "", "confidence": 0.0})

    texts = [text for (_bbox, text, _conf) in results]
    confidences = [conf for (_bbox, _text, conf) in results]
    avg_confidence = sum(confidences) / len(confidences)

    return jsonify({"text": " ".join(texts), "confidence": avg_confidence})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9700)
