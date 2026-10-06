package sidecar

import (
	"context"
	"errors"
	"math"
	"testing"
)

func cos(a, b []float64) float64 {
	var d, x, y float64
	for i := range a {
		d, x, y = d+a[i]*b[i], x+a[i]*a[i], y+b[i]*b[i]
	}
	return d / math.Sqrt(x*y)
}

func TestClientAgainstStub(t *testing.T) {
	base, stop, err := Stub()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ctx := context.Background()
	c := &Client{OCR: base, Face: base, Finger: base}
	if txt, conf, err := c.ExtractText(ctx, []byte("ID 1-1005-00123-45-6")); err != nil || txt != "ID 1-1005-00123-45-6" || conf < 0.9 {
		t.Fatalf("ocr: %q %v %v", txt, conf, err)
	}
	a, ok, _, err := c.EmbedFace(ctx, []byte("face:somchai"))
	b, _, _, _ := c.EmbedFace(ctx, []byte("face:somchai:second-photo"))
	o, _, _, _ := c.EmbedFace(ctx, []byte("face:other"))
	if err != nil || !ok || cos(a, b) < 0.9 || cos(a, o) > 0.5 {
		t.Fatalf("face: same %.3f other %.3f %v", cos(a, b), cos(a, o), err)
	}
	if _, ok, _, _ := c.EmbedFace(ctx, []byte("a cat")); ok {
		t.Fatal("no face")
	}
	tm, err := c.FingerTemplate(ctx, []byte("finger:somchai"))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := c.FingerMatch(ctx, []byte("finger:somchai:again"), tm); s < 0.9 {
		t.Fatal("same finger")
	}
	if s, _ := c.FingerMatch(ctx, []byte("finger:other"), tm); s > 0.1 {
		t.Fatal("other finger")
	}
	if _, err := c.FingerTemplate(ctx, []byte("smudge")); err == nil {
		t.Fatal("no template")
	}
	if h, err := c.ModelSHA256(ctx, base); err != nil || len(h) != 64 {
		t.Fatalf("info: %v", err)
	}
	if _, _, err := (&Client{}).ExtractText(ctx, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatal("not configured")
	}
}
