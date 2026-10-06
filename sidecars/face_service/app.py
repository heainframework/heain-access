"""Face-embedding sidecar for heain-access's face Stage A verifier.

Wraps InsightFace (buffalo_l: a real trained face-detection +
ArcFace-embedding model pipeline, CPU-only here) behind a tiny Flask HTTP
API -- mirroring the Python-sidecar pattern already used by heain-image,
heain-videos, and heain-access's own OCR sidecar. The model does face
detection and produces a face embedding; heain-access's own Go code
(internal/verifier/face.go) does the deterministic half -- comparing two
embeddings by cosine similarity against a threshold.
"""
import base64
import io

from flask import Flask, request, jsonify
import numpy as np
from PIL import Image
import insightface
from insightface.app import FaceAnalysis

app = Flask(__name__)

face_app = FaceAnalysis(name="buffalo_l", providers=["CPUExecutionProvider"])
face_app.prepare(ctx_id=-1, det_size=(640, 640))


@app.route("/embed", methods=["POST"])
def embed():
    data = request.get_json(force=True)
    image_b64 = data.get("image_b64", "")
    if not image_b64:
        return jsonify({"error": "image_b64 is required"}), 400

    try:
        image_bytes = base64.b64decode(image_b64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as exc:
        return jsonify({"error": f"could not decode image: {exc}"}), 400

    # InsightFace expects BGR (OpenCV convention).
    img_array = np.array(image)[:, :, ::-1]
    faces = face_app.get(img_array)

    if not faces:
        return jsonify({"face_detected": False, "embedding": [], "confidence": 0.0})

    # Use the highest-confidence detection when more than one face appears.
    best = max(faces, key=lambda f: f.det_score)
    return jsonify({
        "face_detected": True,
        "embedding": best.normed_embedding.tolist(),
        "confidence": float(best.det_score),
    })


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


_MODEL = {"name": "insightface-buffalo_l", "version": "0.7.3", "sha256": _model_sha256(["~/.insightface/models/buffalo_l/*.onnx"], "insightface " + insightface.__version__ + " buffalo_l")}


@app.route("/info", methods=["GET"])
def info():
    return jsonify({"model": _MODEL})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9701)  # local_only (manifest ai_sidecars)
