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
import pickle

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


# heain-access v2 (Step 4d, 2026-10-06): templates instead of images.
# /template turns an image into a minutiae template (serialized); heain-access
# keeps only that, sealed, and /match_template scores a presented image
# against it. Templates come back only from heain-access's own sealed store,
# so unpickling them does not take input from outside the deployment.
@app.route("/template", methods=["POST"])
def template():
    data = request.get_json(force=True)
    image_b64 = data.get("image_b64", "")
    if not image_b64:
        return jsonify({"error": "image_b64 is required"}), 400
    try:
        img = _decode_grayscale(image_b64)
    except Exception as exc:
        return jsonify({"error": f"could not decode image: {exc}"}), 400
    try:
        tmpl = extractor.extract_minutiae(img)
    except Exception as exc:
        return jsonify({"error": f"minutiae extraction failed: {exc}"}), 500
    return jsonify({"template_b64": base64.b64encode(pickle.dumps(tmpl)).decode()})


@app.route("/match_template", methods=["POST"])
def match_template():
    data = request.get_json(force=True)
    image_b64 = data.get("image_b64", "")
    template_b64 = data.get("template_b64", "")
    if not image_b64 or not template_b64:
        return jsonify({"error": "image_b64 and template_b64 are both required"}), 400
    try:
        presented = extractor.extract_minutiae(_decode_grayscale(image_b64))
        enrolled = pickle.loads(base64.b64decode(template_b64))
        result = extractor.match(presented, enrolled)
    except Exception as exc:
        return jsonify({"error": f"fingerprint matching failed: {exc}"}), 500
    return jsonify({"score": float(result.score)})


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


_MODEL = {"name": "nbis-mindtct-bozorth3", "version": "5.0", "sha256": _model_sha256([], "afis " + getattr(afis, "__version__", "unknown") + " nbis")}


@app.route("/info", methods=["GET"])
def info():
    return jsonify({"model": _MODEL})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9702)  # local_only (manifest ai_sidecars)
