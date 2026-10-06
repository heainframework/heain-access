package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Stub is a TEST-ONLY stand-in for the three sidecars (heain-access
// -test-stub-sidecars), deterministic and model-free, so the conformance
// suite and the flow tests run without Python or model weights:
//   - OCR: the "image" bytes are the text (confidence 0.95);
//   - face: "face:<who>[:<variant>]" -> a unit vector derived from <who>,
//     slightly perturbed by <variant> (same person, another photo); any
//     other image has no face;
//   - fingerprint: "finger:<who>[:<variant>]" -> template <who>; a match
//     scores 0.95 for the same <who>, 0.05 otherwise.
//
// It listens on 127.0.0.1 only and returns the base URL.
func Stub() (string, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	mux := http.NewServeMux()
	type in struct {
		Image    []byte `json:"image_b64"`
		Template []byte `json:"template_b64"`
	}
	read := func(r *http.Request) in {
		var v in
		_ = json.NewDecoder(r.Body).Decode(&v)
		return v
	}
	reply := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	parts := func(b []byte, kind string) (string, string, bool) {
		s := string(b)
		if !strings.HasPrefix(s, kind+":") {
			return "", "", false
		}
		p := strings.SplitN(strings.TrimPrefix(s, kind+":"), ":", 2)
		v := ""
		if len(p) == 2 {
			v = p[1]
		}
		return p[0], v, p[0] != ""
	}
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.Sum256([]byte("heain-access test stub sidecar v1 (no model)"))
		reply(w, map[string]any{"model": map[string]any{"name": "test-stub", "version": "1", "sha256": hex.EncodeToString(h[:])}})
	})
	mux.HandleFunc("/extract", func(w http.ResponseWriter, r *http.Request) {
		v := read(r)
		if !utf8.Valid(v.Image) {
			reply(w, map[string]any{"text": "", "confidence": 0})
			return
		}
		reply(w, map[string]any{"text": string(v.Image), "confidence": 0.95})
	})
	mux.HandleFunc("/embed", func(w http.ResponseWriter, r *http.Request) {
		who, variant, ok := parts(read(r).Image, "face")
		if !ok {
			reply(w, map[string]any{"face_detected": false, "embedding": []float64{}, "confidence": 0})
			return
		}
		e := make([]float64, 64)
		for i := range e {
			h := sha256.Sum256([]byte(who + string(rune(i))))
			e[i] = float64(int64(binary.BigEndian.Uint64(h[:8])>>11))/float64(1<<52) - 1
			if variant != "" {
				n := sha256.Sum256([]byte(variant + string(rune(i))))
				e[i] += 0.15 * (float64(n[0])/255 - 0.5)
			}
		}
		var s float64
		for _, x := range e {
			s += x * x
		}
		for i := range e {
			e[i] /= math.Sqrt(s)
		}
		reply(w, map[string]any{"face_detected": true, "embedding": e, "confidence": 0.99})
	})
	mux.HandleFunc("/template", func(w http.ResponseWriter, r *http.Request) {
		who, _, ok := parts(read(r).Image, "finger")
		if !ok {
			reply(w, map[string]any{"template_b64": []byte{}})
			return
		}
		reply(w, map[string]any{"template_b64": []byte("stub-template:" + who)})
	})
	mux.HandleFunc("/match_template", func(w http.ResponseWriter, r *http.Request) {
		v := read(r)
		who, _, ok := parts(v.Image, "finger")
		score := 0.05
		if ok && string(v.Template) == "stub-template:"+who {
			score = 0.95
		}
		reply(w, map[string]any{"score": score})
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	return "http://" + l.Addr().String(), func() { _ = srv.Close() }, nil
}
