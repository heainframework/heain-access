// Command heain-access runs the standalone access-control HTTP service.
// Stage A registers only the keycard Verifier, the one Stage A method
// whose Allow decision is genuinely deterministic and needs no model
// choice to ship. The other four methods (ID card, face, fingerprint,
// DCP/KDM key issuance) are registered once their model-backed
// implementations exist.
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

	st := store.NewInMemoryStore()
	srv := httpapi.NewServer(reg, st)

	log.Printf("heain-access: listening on %s (keycard verifier registered with %d allowed UID(s))",
		*listenAddr, len(uids))
	if err := http.ListenAndServe(*listenAddr, srv.Routes()); err != nil {
		log.Fatalf("heain-access: %v", err)
	}
}
