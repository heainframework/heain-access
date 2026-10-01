// Command heain-access runs the standalone access-control HTTP service.
// Stage A registers the keycard Verifier (the one Stage A method whose
// Allow decision is genuinely deterministic and needs no model choice to
// ship) plus id_card, face, and fingerprint once their respective sidecar
// URLs are configured. The remaining method (DCP/KDM key issuance) is
// registered once its implementation exists.
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
	fingerprintSidecarURL := flag.String("fingerprint-sidecar-url", "",
		"base URL of the fingerprint-matching sidecar (SourceAFIS) backing the fingerprint Verifier "+
			"(e.g. http://localhost:9702); fingerprint is not registered when empty")
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

	fingerprintRegistered := false
	if *fingerprintSidecarURL != "" {
		if err := reg.Register(verifier.NewFingerprintVerifier(*fingerprintSidecarURL)); err != nil {
			log.Fatalf("heain-access: registering fingerprint verifier: %v", err)
		}
		fingerprintRegistered = true
	}

	st := store.NewInMemoryStore()
	srv := httpapi.NewServer(reg, st)

	log.Printf("heain-access: listening on %s (keycard verifier registered with %d allowed UID(s); id_card verifier registered: %v; face verifier registered: %v; fingerprint verifier registered: %v)",
		*listenAddr, len(uids), idCardRegistered, faceRegistered, fingerprintRegistered)
	if err := http.ListenAndServe(*listenAddr, srv.Routes()); err != nil {
		log.Fatalf("heain-access: %v", err)
	}
}
