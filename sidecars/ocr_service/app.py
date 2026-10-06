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


# heain-sidecar/v1 /info (Step 4d, 2026-10-06): the hash of the weights actually loaded,
# for heain-access's reasoning records (spec 04 model hash).
def _model_sha256(paths, fallback):
    import glob, hashlib, os
    h = hashlib.sha256()
    files = sorted(f for p in paths for f in glob.glob(os.path.expanduser(p), recursive=True) if os.path.isfile(f))
    for f in files:
        with open(f, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    if not files:
        h.update(fallback.encode())
    return h.hexdigest()


_MODEL = {"name": "easyocr-th-en", "version": "1.7", "sha256": _model_sha256(["~/.EasyOCR/model/*.pth"], "easyocr " + easyocr.__version__ + " th,en")}


@app.route("/info", methods=["GET"])
def info():
    return jsonify({"model": _MODEL})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9700)  # local_only (manifest ai_sidecars)
