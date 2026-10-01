"""Fingerprint-matching sidecar for heain-access's fingerprint Stage A
verifier.

Wraps NIST NBIS (MINDTCT minutiae extraction + Bozorth3 matching, via the
`afis` Python package) -- a production-grade classical AFIS engine that is
itself the reference implementation used in real government AFIS systems,
not a toy feature-matcher, per the user's explicit requirement. (SourceAFIS
itself has no official Python port -- only Java and .NET -- so this sidecar
uses NBIS instead; see claude/progress-log.md in the project docs for the
full rationale and the live API verification that led here.)

Returns afis's own normalized MatchResult.score (in [0,1]), not its
unbounded raw_score -- FingerprintVerifier on the Go side compares this
against DefaultFingerprintMatchThreshold (0.8, afis's own documented
default for the nbis_bozorth3 matcher).
"""
import base64
import io

import numpy as np
from flask import Flask, request, jsonify
from PIL import Image

import afis

app = Flask(__name__)

extractor = afis.NbisExtractor()


def _decode_grayscale(image_b64):
    image_bytes = base64.b64decode(image_b64)
    image = Image.open(io.BytesIO(image_bytes)).convert("L")
    return np.array(image, dtype=np.uint8)


@app.route("/match", methods=["POST"])
def match():
    data = request.get_json(force=True)
    presented_b64 = data.get("presented_image_b64", "")
    enrolled_b64 = data.get("enrolled_image_b64", "")
    if not presented_b64 or not enrolled_b64:
        return jsonify({"error": "presented_image_b64 and enrolled_image_b64 are both required"}), 400

    try:
        presented_img = _decode_grayscale(presented_b64)
        enrolled_img = _decode_grayscale(enrolled_b64)
    except Exception as exc:
        return jsonify({"error": f"could not decode image: {exc}"}), 400

    try:
        presented_template = extractor.extract_minutiae(presented_img)
        enrolled_template = extractor.extract_minutiae(enrolled_img)
        result = extractor.match(presented_template, enrolled_template)
    except Exception as exc:
        return jsonify({"error": f"fingerprint matching failed: {exc}"}), 500

    return jsonify({"score": float(result.score)})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9702)
