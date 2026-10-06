// Command heain-access is the identity-verification and access-grant base
// app: face and fingerprint enrolment (templates only, sealed, retention at
// most 30 days) and matching, ID-card OCR with an optional registry check
// in heain-database, keycards against an ACL dataset in heain-database, and
// signed AccessGrants. The AI models run as local sidecars (heain-sidecar/v1).
// The dcp-key plugin (KDM issuance for cinema packages) is optional.
// Configured through the heain-sdk HEAIN_* variables; runs however the
// operator likes: a plain process, a service unit, or a container.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-access/internal/api"
	"github.com/heainframework/heain-access/internal/biometric"
	"github.com/heainframework/heain-access/internal/grants"
	"github.com/heainframework/heain-access/internal/plugins/dcpkey"
	"github.com/heainframework/heain-access/internal/sidecar"
)

func main() {
	ocr := flag.String("ocr-sidecar-url", "http://127.0.0.1:9700", "OCR sidecar (EasyOCR), localhost only")
	face := flag.String("face-sidecar-url", "http://127.0.0.1:9701", "face sidecar (InsightFace), localhost only")
	finger := flag.String("fingerprint-sidecar-url", "http://127.0.0.1:9702", "fingerprint sidecar (NBIS), localhost only")
	stub := flag.Bool("test-stub-sidecars", false, "TEST ONLY: deterministic model-free stand-ins for the three sidecars")
	faceThr := flag.Float64("face-threshold", 0.5, "minimum cosine similarity for a face match")
	fpThr := flag.Float64("fingerprint-threshold", 0.8, "minimum match score for a fingerprint match")
	retention := flag.Duration("retention", 30*24*time.Hour, "how long an enrolled template is kept (at most 720h, the manifest's retention max)")
	aclDS := flag.String("keycard-acl-dataset", "keycards", "heain-database dataset holding allowed keycard UIDs")
	aclScope := flag.String("keycard-acl-scope", "default", "its scope_key")
	dcpCA := flag.String("dcp-key-ca-file", "", "dcp-key plugin: trusted root(s) for target playback-device certificates (plugin off when empty)")
	dcpCert := flag.String("dcp-key-issuer-cert-file", "", "dcp-key plugin: issuer certificate chain, leaf first (the KDM signer)")
	dcpCallers := flag.String("dcp-key-callers", "heain-mastering", "dcp-key plugin: comma-separated apps allowed to ask for KDMs")
	dcpKey := flag.String("dcp-key-issuer-key-file", "", "dcp-key plugin: issuer RSA key")
	flag.Parse()
	if *retention <= 0 || *retention > 30*24*time.Hour {
		log.Fatal("heain-access: -retention must be within 0..720h (manifest biometric_template retention max 30d)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-access: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	state := os.Getenv("HEAIN_STATE_DIR")
	if state == "" {
		state = "/state"
	}
	ik, err := app.DataKey(ctx, "inside")
	if err != nil {
		log.Fatalf("heain-access: data key from core: %v", err)
	}
	inside, err := heain.NewSealer(ik)
	if err != nil {
		log.Fatal(err)
	}
	bio, err := biometric.Open(filepath.Join(state, "templates.db"), inside, ik, biometric.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey})
	if err != nil {
		log.Fatal(err)
	}
	defer bio.Close()
	gs, err := grants.Open(filepath.Join(state, "grants.db"), inside, app)
	if err != nil {
		log.Fatal(err)
	}
	defer gs.Close()
	side := &sidecar.Client{OCR: *ocr, Face: *face, Finger: *finger}
	runtime := "sidecars heain-sidecar/v1 (EasyOCR, InsightFace buffalo_l, NBIS)"
	if *stub {
		base, stopStub, err := sidecar.Stub()
		if err != nil {
			log.Fatal(err)
		}
		defer stopStub()
		side = &sidecar.Client{OCR: base, Face: base, Finger: base}
		runtime = "TEST STUB sidecars (no model)"
		log.Printf("heain-access: WARNING -test-stub-sidecars: model-free stand-ins, TEST ONLY")
	}
	a := &api.API{App: app, Side: side, Bio: bio, Grants: gs, Runtime: runtime, FaceThreshold: *faceThr, FingerThreshold: *fpThr,
		Retention: *retention, ACLDataset: *aclDS, ACLScope: *aclScope}
	if *dcpCA != "" {
		caPEM, err1 := os.ReadFile(*dcpCA)
		certPEM, err2 := os.ReadFile(*dcpCert)
		keyPEM, err3 := os.ReadFile(*dcpKey)
		if err1 != nil || err2 != nil || err3 != nil {
			log.Fatalf("heain-access: dcp-key plugin files: %v %v %v", err1, err2, err3)
		}
		if a.KDM, err = dcpkey.New(caPEM, certPEM, keyPEM); err != nil {
			log.Fatalf("heain-access: dcp-key plugin: %v", err)
		}
		a.KDMCallers = map[string]bool{}
		for _, c := range strings.Split(*dcpCallers, ",") {
			if c = strings.TrimSpace(c); c != "" {
				a.KDMCallers[c] = true
			}
		}
		log.Printf("heain-access: plugin dcp-key enabled (SMPTE 430-1 KDMs, callers %s)", *dcpCallers)
	}
	srv := app.NewServer()
	if err := a.Register(srv); err != nil {
		log.Fatal(err)
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if n, err := bio.Sweep(ctx); err != nil {
				log.Printf("heain-access: retention sweep: %v", err)
			} else if n > 0 {
				log.Printf("heain-access: retention sweep removed %d template(s)", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	l, err := net.Listen("tcp", heain.Listen(":19480"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-access: active, serving on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-access: deregistered")
}
