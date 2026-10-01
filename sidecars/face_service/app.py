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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9701)
