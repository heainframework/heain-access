// Command heain-access runs the standalone access-control HTTP service.
// Stage A registers the keycard Verifier (deterministic ACL gate) and,
// when the corresponding sidecar URL flags are set, the id_card and face
// Verifiers (real ML via Python sidecars). The remaining two methods
// (fingerprint, DCP/KDM key issuance) are registered once their
// model-backed implementations exist.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/heainframework/heain-access/internal/httpapi"
	"github.com/heainframework/heain-access/internal/store"
	"github.com/heainframework/heain-access/internal/verifier"
)

func main() {
	listenAddr := flag.String("listen-addr", ":8086", "address for heain-access to listen on")
	allowedKeycardUIDs := flag.String("allowed-keycard-uids", "",
		"comma-separated keycard UIDs allowed by the keycard Verifier "+
			"(Stage A bootstrap; a real ACL store replaces this flag later)")
	ocrSidecarURL := flag.String("ocr-sidecar-url", "",
		"base URL of the OCR sidecar backing the id_card Verifier (e.g. http://localhost:9700); "+
			"id_card is not registered when empty")
	faceSidecarURL := flag.String("face-sidecar-url", "",
		"base URL of the face-embedding sidecar backing the face Verifier (e.g. http://localhost:9701); "+
			"face is not registered when empty")
	flag.Parse()

	reg := verifier.NewRegistry()

	var uids []string
	for _, uid := range strings.Split(*allowedKeycardUIDs, ",") {
		uid = strings.TrimSpace(uid)
		if uid != "" {
			uids = append(uids, uid)
		}
	}
	if err := reg.Register(verifier.NewKeycardVerifier(uids)); err != nil {
		log.Fatalf("heain-access: registering keycard verifier: %v", err)
	}

	idCardRegistered := false
	if *ocrSidecarURL != "" {
		if err := reg.Register(verifier.NewIDCardVerifier(*ocrSidecarURL)); err != nil {
			log.Fatalf("heain-access: registering id_card verifier: %v", err)
		}
		idCardRegistered = true
	}

	faceRegistered := false
	if *faceSidecarURL != "" {
		if err := reg.Register(verifier.NewFaceVerifier(*faceSidecarURL)); err != nil {
			log.Fatalf("heain-access: registering face verifier: %v", err)
		}
		faceRegistered = true
	}

	st := store.NewInMemoryStore()
	srv := httpapi.NewServer(reg, st)

	log.Printf("heain-access: listening on %s (keycard verifier registered with %d allowed UID(s); id_card verifier registered: %v; face verifier registered: %v)",
		*listenAddr, len(uids), idCardRegistered, faceRegistered)
	if err := http.ListenAndServe(*listenAddr, srv.Routes()); err != nil {
		log.Fatalf("heain-access: %v", err)
	}
}
