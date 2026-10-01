// Command heain-access runs the standalone access-control HTTP service.
// Stage A registers all five verification methods: keycard (always on --
// the one method whose Allow decision is genuinely deterministic and
// needs no model choice to ship), id_card/face/fingerprint once their
// respective ML sidecar URLs are configured, and dcp_key (DCP/KDM key
// issuance -- itself deterministic/cryptographic, no sidecar needed) once
// its CA/issuer certificate and key files are configured. This completes
// heain-access's Stage A verifier set.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
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
	dcpKeyCAFile := flag.String("dcp-key-ca-file", "",
		"path to a PEM file of trusted root/intermediate certificate(s) for the dcp_key Verifier "+
			"to check a presented target playback-device (SPB) certificate against; "+
			"dcp_key is not registered unless this and -dcp-key-issuer-cert-file/-dcp-key-issuer-key-file are all set")
	dcpKeyIssuerCertFile := flag.String("dcp-key-issuer-cert-file", "",
		"path to heain-access's own PEM certificate, used to sign every KDM the dcp_key Verifier issues")
	dcpKeyIssuerKeyFile := flag.String("dcp-key-issuer-key-file", "",
		"path to heain-access's own PEM RSA private key (PKCS#1 or PKCS#8), matching -dcp-key-issuer-cert-file")
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

	dcpKeyRegistered := false
	if *dcpKeyCAFile != "" || *dcpKeyIssuerCertFile != "" || *dcpKeyIssuerKeyFile != "" {
		if *dcpKeyCAFile == "" || *dcpKeyIssuerCertFile == "" || *dcpKeyIssuerKeyFile == "" {
			log.Fatalf("heain-access: -dcp-key-ca-file, -dcp-key-issuer-cert-file, and -dcp-key-issuer-key-file must all be set together")
		}
		caPEM, err := os.ReadFile(*dcpKeyCAFile)
		if err != nil {
			log.Fatalf("heain-access: reading -dcp-key-ca-file: %v", err)
		}
		issuerCertPEM, err := os.ReadFile(*dcpKeyIssuerCertFile)
		if err != nil {
			log.Fatalf("heain-access: reading -dcp-key-issuer-cert-file: %v", err)
		}
		issuerKeyPEM, err := os.ReadFile(*dcpKeyIssuerKeyFile)
		if err != nil {
			log.Fatalf("heain-access: reading -dcp-key-issuer-key-file: %v", err)
		}
		dcpKeyVerifier, err := verifier.NewDCPKeyVerifier(caPEM, issuerCertPEM, issuerKeyPEM)
		if err != nil {
			log.Fatalf("heain-access: constructing dcp_key verifier: %v", err)
		}
		if err := reg.Register(dcpKeyVerifier); err != nil {
			log.Fatalf("heain-access: registering dcp_key verifier: %v", err)
		}
		dcpKeyRegistered = true
	}

	st := store.NewInMemoryStore()
	srv := httpapi.NewServer(reg, st)

	log.Printf("heain-access: listening on %s (keycard verifier registered with %d allowed UID(s); id_card verifier registered: %v; face verifier registered: %v; fingerprint verifier registered: %v; dcp_key verifier registered: %v)",
		*listenAddr, len(uids), idCardRegistered, faceRegistered, fingerprintRegistered, dcpKeyRegistered)
	if err := http.ListenAndServe(*listenAddr, srv.Routes()); err != nil {
		log.Fatalf("heain-access: %v", err)
	}
}
